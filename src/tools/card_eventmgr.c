/*
    Generate events on card status change
    Copyrigt (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
    Based on pcsc_scan tool by Ludovic Rousseau <ludovic.rousseau@free.fr>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

/* $Id: card_eventmgr.c,v 1.13 2004/04/02 06:44:38 rousseau Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <pcsclite.h>
#include <wintypes.h>
#include <winscard.h>

#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define DEF_TIMEOUT 1000    /* 1 second timeout */
#define DEF_CONFIG_FILE "/etc/pam_pkcs11/card_eventmgr.conf"

#define ONERROR_IGNORE	0
#define ONERROR_RETURN	1
#define ONERROR_QUIT	2

int timeout;
int timeout_count;
int timeout_limit;
int daemonize;
int debug;
char *cfgfile;
scconf_context *ctx = NULL;
const scconf_block *root;
SCARDCONTEXT hContext;
char *pidfile = NULL;
char AraKiri = FALSE;

void thats_all_folks() {
    int rv;
    DBG("Exitting");
    /* We try to leave things as clean as possible */
    rv = SCardReleaseContext(hContext);
    if (rv != SCARD_S_SUCCESS) {
        DBG1("SCardReleaseContext: %lX", rv);
    }

    /* free configuration context */
    if (ctx)
	scconf_free(ctx);
}

int my_system(char *command) {
	extern char **environ;
	int pid, status;
	   if (!command) return 1;
           pid = fork();
           if (pid == -1) return -1;
           if (pid == 0) {
               char *argv[4];
               argv[0] = "/bin/sh";
               argv[1] = "-c";
               argv[2] = command;
               argv[3] = 0;
               execve("/bin/sh", argv, environ);
               exit(127);
           }
           do {
               if (waitpid(pid, &status, 0) == -1) {
                   if (errno != EINTR) return -1;
               } else return status;
           } while(1);
}

int execute_event (char *action) {
	int onerr;
	const char *onerrorstr;
	const scconf_list *actionlist;
	scconf_block **blocklist, *myblock;
	blocklist = scconf_find_blocks(ctx,root,"event",action);
        if (!blocklist) {
                DBG("Event block list not found");
	        return -1;
	}
	myblock=blocklist[0];
	free(blocklist);
	if (!myblock) {
		DBG1("Event item not found: '%s'",action);
		return -1;
	}
	onerrorstr = scconf_get_str(myblock,"on_error","ignore");
	if(!strcmp(onerrorstr,"ignore")) onerr = ONERROR_IGNORE;
	else if(!strcmp(onerrorstr,"return")) onerr = ONERROR_RETURN;
	else if(!strcmp(onerrorstr,"quit")) onerr = ONERROR_QUIT;
	else {
	    onerr = ONERROR_IGNORE;
	    DBG1("Invalid onerror value: '%s'. Assumed 'ignore'",onerrorstr);
	}
	/* search actions */
	actionlist = scconf_find_list(myblock,"action");
	if (!actionlist) {
	        DBG1("No action list for event '%s'",action);
		return 0;
	} 
	DBG1("Onerror is set to: '%s'",onerrorstr);
	while (actionlist) {
		int res;
		char *action_cmd= actionlist->data;
		DBG1("Executiong action: '%s'",action_cmd);
		/*
		there are some security issues on using system() in 
		setuid/setgid programs. so we will use an alternate function
                */ 
		/* res=system(action_cmd); */
		res = my_system(action_cmd);
		actionlist=actionlist->next;
		/* evaluate return and take care on "onerror" value */
		DBG2("Action '%s' returns %d",action_cmd, res);
		if (!res) continue;
		switch(onerr) {
		    case ONERROR_IGNORE: continue;
		    case ONERROR_RETURN: return 0;
		    case ONERROR_QUIT: 	thats_all_folks();
					exit(0); 
		    default: 		DBG("Invalid onerror value");
			     		return -1;		   
		}
	}
	return 0;
}

int parse_config_file() {
        ctx = scconf_new(cfgfile);
        if (!ctx) {
           DBG("Error creating conf context");
           return -1;
        }
        if ( scconf_parse(ctx) <=0 ) {
           DBG1("Error parsing file '%s'",cfgfile);
           return -1;
        }
        /* now parse options */
        root = scconf_find_block(ctx, NULL, "card_eventmgr");
        if (!root) {
           DBG1("card_eventmgr block not found in config: '%s'",cfgfile);
           return -1;
        }
	debug = scconf_get_bool(root,"debug",debug);
	daemonize = scconf_get_bool(root,"daemon",daemonize);
	timeout = scconf_get_int(root,"timeout",timeout);
	timeout_limit = scconf_get_int(root,"timeout_limit",0);
	if (debug) set_debug_level(1);
	return 0;
}

int parse_args(int argc, char *argv[]) {
	int i;
	timeout = DEF_TIMEOUT;
	timeout_limit = 0;
	debug   = 0;
	daemonize  = 0;
	cfgfile = DEF_CONFIG_FILE;
        /* first of all check whether debugging should be enabled */
        for (i = 0; i < argc; i++) {
          if (! strcmp("debug", argv[i])) set_debug_level(1);
        }
        /* try to find a configuration file entry */
        for (i = 0; i < argc; i++) {
            if (strstr(argv[i],"config_file=") ) {
                cfgfile=1+strchr(argv[i],'=');
                break;
            }
        }
	/* parse configuration file */
	if ( parse_config_file()<0) {
		fprintf(stderr,"Error parsing configuration file %s\n",cfgfile);
		exit(-1);
	}

	/* and now re-parse command line to take precedence over cfgfile */
        for (i = 1; i < argc; i++) {
	    int res;
            if (strcmp("daemon", argv[i]) == 0) {
		daemonize=1;
	  	continue;
	    }
            if (strcmp("nodaemon", argv[i]) == 0) {
		daemonize=0;
	  	continue;
	    }
            if (strcmp("kill", argv[i]) == 0) {
		AraKiri=TRUE;
	  	continue;
	    }
            if (strstr(argv[i],"timeout=") ) {
                res=sscanf(argv[i],"timeout=%d",&timeout);
                continue;
            }
            if (strstr(argv[i],"timeout_limit=") ) {
                res=sscanf(argv[i],"timeout_limit=%d",&timeout_limit);
                continue;
            }
	    if (strstr(argv[i],"pidfile=") ) {
		 pidfile = strchr(argv[i],'=') +1;
		continue;
	    }
            if (strstr(argv[i],"debug") ) {
		continue;  /* already parsed: skip */
	    }
            if (strstr(argv[i],"nodebug") ) {
		continue;  /* already parsed: skip */
	    }
            if (strstr(argv[i],"config_file=") ) {
		continue; /* already parsed: skip */
	    }
	    fprintf(stderr,"unknown option %s\n",argv[i]);
	    /* arriving here means syntax error */
	    fprintf(stderr,"Usage %s [[no]debug] [[no]daemon] [timeout=<timeout>] [timeout_limit=<limit>] [config_file=<file>] [kill] [pidfile=<file>]\n",argv[0]);
	    fprintf(stderr,"Defaults: debug=0 daemon=0 timeout=%d (ms) timeout_limit=0 (none) config_file=%s\n",DEF_TIMEOUT,DEF_CONFIG_FILE );
	    exit(1);
        } /* for */
	/* end of config: return */
	return 0;
}

pid_t read_pidfile(char *filename)
{
    FILE *fd;
    pid_t pid;
    int res;
    long temp = 0;

    fd = fopen(filename, "r");
    if (NULL == fd)
    {
	DBG2("Can't read pidfile %s: %s", filename, strerror(errno));
	return 0;
    }

    res=fscanf(fd, "%ld", &temp);
    pid = temp;

    fclose(fd);

    return pid;
}

void remove_pidfile(char *filename)
{
    if (unlink(filename))
	DBG2("Can't unlink pidfile %s: %s", filename, strerror(errno));
}

void create_pidfile(char *filename)
{
    int fd;
    int res;
    char tmp[20];

    fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
    {
	DBG2("Can't create pidfile %s: %s", filename, strerror(errno));
	return;
    }

    snprintf(tmp, sizeof(tmp)-1, "%d\n", getpid());
    tmp[sizeof(tmp)-1] = '\0';

    res=write(fd, tmp, strlen(tmp));

    close(fd);
}

void signal_trap(int sig)
{
    if (FALSE == AraKiri)
    {
	DBG("Preparing to suicide");
	AraKiri = TRUE;
    }
}

int main(int argc, char *argv[]) {
    int current_reader;
    LONG rv;
    SCARD_READERSTATE_A *rgReaderStates_t = NULL;
    DWORD dwReaders, dwReadersOld;
    LPSTR mszReaders = NULL;
    char *ptr, **readers = NULL;
    int nbReaders, i;
    int first_loop = TRUE;

    parse_args(argc,argv);

    /* AraKiri is set if kill argument is passed */
    if (AraKiri)
    {
	/* we are asked to kill the previous pkcs11_eventmgr */
	if (pidfile)
	{
	    pid_t pid = read_pidfile(pidfile);
	    if (pid > 0)
	    {
		DBG1("Killing process: %ld", pid);
	    	kill(pid, SIGQUIT);
	    }
	    else
		DBG("Invalid pid");
	}
	else
	    DBG("You need to specify a pidfile");
	return 0;
    }

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (rv != SCARD_S_SUCCESS) {
        DBG1("SCardEstablishContext: Cannot Connect to Resource Manager %lX", rv);
	if (ctx) scconf_free(ctx);
        return 1;
    }
    
    /* put my self into background if flag is set */
    if (daemonize) {
	DBG("Going to be daemon...");
	if ( daemon(0,debug)<0 ) {
		DBG1("Error in daemon() call: %s", strerror(errno));
		goto end;
	}
    }

    signal(SIGINT, signal_trap);
    signal(SIGQUIT, signal_trap);
    signal(SIGTERM, signal_trap);

    if (pidfile)
	create_pidfile(pidfile);

get_readers:
    /* free memory possibly allocated in a previous loop */
    /* free() already check if pt is null, so no check needed */
    free(readers);
    free(rgReaderStates_t);

    /* Retrieve the available readers list.
     *
     * 1. Call with a null buffer to get the number of bytes to allocate
     * 2. malloc the necessary storage
     * 3. call with the real allocated buffer
     */
    DBG("Scanning present readers");
    rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
    if (rv != SCARD_S_SUCCESS) {
        DBG1("SCardListReader: %lX", rv);
    }
    dwReadersOld = dwReaders;

    /* if non NULL we came back so free first */
    free(mszReaders);

    mszReaders = malloc(sizeof(char)*dwReaders);
    if (mszReaders == NULL) {
        DBG("malloc: not enough memory");
        goto end;
    }

    rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
    if (rv != SCARD_S_SUCCESS) {
        DBG1("SCardListReader: %lX", rv);
    }

    /* Extract readers from the null separated string and get the total
     * number of readers */
    nbReaders = 0;
    ptr = mszReaders;
    while (*ptr != '\0') {
        ptr += strlen(ptr)+1;
        nbReaders++;
    }

    if (nbReaders == 0) {
    	/* exit if no reader is present at startup */
	if (first_loop) {
	    printf("%s: No reader present, exiting\n", argv[0]);
	    goto end;
	}

        DBG("Waiting for the first reader...");
        while ((SCardListReaders(hContext, NULL, NULL, &dwReaders)
            == SCARD_S_SUCCESS) && (dwReaders == dwReadersOld))
            sleep(1);
        DBG("found one");
        goto get_readers;
    }

    /* allocate the readers table */
    readers = calloc(nbReaders, sizeof(char *));
    if (! readers) {
        DBG("Not enough memory for readers table");
        goto end;
    }

    /* fill the readers table */
    nbReaders = 0;
    ptr = mszReaders;
    while (*ptr != '\0') {
        DBG2("%d: %s", nbReaders, ptr);
        readers[nbReaders] = ptr;
        ptr += strlen(ptr)+1;
        nbReaders++;
    }

    /* allocate the ReaderStates table */
    rgReaderStates_t = calloc(nbReaders, sizeof(* rgReaderStates_t));
    if (! rgReaderStates_t) {
        DBG("Not enough memory for readers states");
        goto end;
    }

    /* Set the initial states to something we do not know
     * The loop below will include this state to the dwCurrentState
     */
    for (i=0; i<nbReaders; i++) {
        rgReaderStates_t[i].szReader = readers[i];
        rgReaderStates_t[i].dwCurrentState = SCARD_STATE_UNAWARE;
    }

    /* Wait endlessly for all events in the list of readers
     * We only stop in case of an error
     */
    rv = SCardGetStatusChange(hContext, timeout, rgReaderStates_t, nbReaders);
    while ((rv == SCARD_S_SUCCESS) || (rv == SCARD_E_TIMEOUT)) {
        /* A new reader appeared? */
        if ((SCardListReaders(hContext, NULL, NULL, &dwReaders)
            == SCARD_S_SUCCESS) && (dwReaders != dwReadersOld))
                goto get_readers;

	   /* we were asked to suicide */
	   if (AraKiri)
		break;

        /* Now we have an event, check all the readers to see what happened */
        for (current_reader=0; current_reader < nbReaders; current_reader++) {
	    unsigned long new_state;

            if (rgReaderStates_t[current_reader].dwEventState &
                SCARD_STATE_CHANGED) {
                /* If something has changed the new state is now the current
                 * state */
                rgReaderStates_t[current_reader].dwCurrentState =
                    rgReaderStates_t[current_reader].dwEventState;
            }
            /* If nothing changed then skip to the next reader */
            else continue;

            /* From here we know that the state for the current reader has
             * changed because we did not pass through the continue statement
             * above.
             */

	    if (first_loop)
		continue; /* skip first pass */

            /* Specify the current reader's number and name */
            DBG2("Reader %d (%s)", current_reader,
                rgReaderStates_t[current_reader].szReader);

            /* Dump the full current state */
	    new_state = rgReaderStates_t[current_reader].dwEventState;
            DBG1("Card state: 0x%08ld", new_state);

            if (new_state & SCARD_STATE_UNKNOWN) {
                DBG("Reader unknown");
                goto get_readers;
            }

            if (new_state & SCARD_STATE_EMPTY) {
                    DBG("Card removed");
		    execute_event("card_remove");
            }

            if (new_state & SCARD_STATE_PRESENT) {
                    DBG("Card inserted");
		    execute_event("card_insert");
            }
        } /* for */

	first_loop = FALSE;
        rv = SCardGetStatusChange(hContext, timeout, rgReaderStates_t, nbReaders);
    } /* while */

    /* If we get out the loop, GetStatusChange() was unsuccessful */
    DBG1("SCardGetStatusChange: %lX", rv);

end:
    /* free memory possibly allocated */
    free(readers);
    free(rgReaderStates_t);

    if (pidfile)
	remove_pidfile(pidfile);

    thats_all_folks();
    exit(0);
} /* main */

