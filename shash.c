//shash.c
//monofuel
//CS 5950

#define DEBUG 1

#include <time.h>
#include "shash.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <openssl/evp.h>

extern char **environ;
env_spec ** env_spec_list = NULL;

FILE * log_file = NULL;

int main(int argc, char** argv) {
  if (DEBUG) printf("DEBUG: starting\n");
  //clear environment
  cleanup();
  if (DEBUG) printf("DEBUG: cleaned up environment\n");
  //read config
  load_config();
  if (DEBUG) printf("DEBUG: loaded config\n");
  //invoke commands
  run();
  if (log_file != NULL) fclose(log_file);
  return EXIT_SUCCESS;
}

/*
 * Bail out from the program without displaying
 * errors. Typically should be used with
 * explaining the error in audit_log instead
 */
void silent_exit() {
  audit_log("Silent Exit\n");
  if (log_file != NULL) fclose(log_file);
  printf("Silent Exit\n");
  exit(EXIT_FAILURE);

}

/*
 * Output to the audit_log.
 * Does not add it's own \n, appends directly
 * to .shashlog
 */
void audit_log(char * info) {
  size_t count = 1;
  size_t length = strlen(info);

  if (log_file == NULL) {
    log_file = fopen(".shashlog","w");
  }
  fwrite(info,length,count,log_file);

  //verify output is generated if the program crashes
  fflush(log_file);
}

//--------------------------------------------
//borrowed from clean.c
//with a few modifications
void cleanup() {
  int i;

	i = -1;

	while (environ[++i] != 0);
  if (DEBUG) printf("DEBUG: prevous environment had %d elements\n",i);
	while (i--) environ[i] = 0;

}
//--------------------------------------------

void load_config() {
  FILE * config;
  char * line = NULL;
  size_t length = 0;
  ssize_t read;
  int env_size = 0;

  config = fopen(".shash.config","r");
  if (config == NULL) {
    silent_exit();
  }

  //check permissions on config
  struct stat file_stat;
  stat(".shash.config",&file_stat);

  if ((file_stat.st_mode & 0022) != 0) {
    if (DEBUG) printf("config is world or group writable\n");
    log_command("[loading config]");
    silent_exit();
  }

  env_spec_list = (env_spec **) malloc(sizeof(env_spec *) * ++env_size);
  env_spec_list[0] = (env_spec *) NULL;

  while ((read = getline(&line,&length,config)) != -1) {
    if (DEBUG) printf("DEBUG: creating new environment description\n");

    //trim newline
    delete_newlines(line);

    //check for a command. if there is, this is invalid.
    if (line[0] == '*') {
      if (DEBUG) printf("DEBUG: got command when expected environment\n");
      audit_log("DEBUG: got command when expected environment\n");
      silent_exit();
    }
    env_spec_list = (env_spec **) realloc(env_spec_list,++env_size * sizeof(env_spec *));
    env_spec * current_env = (env_spec *) malloc(sizeof(env_spec) * 1);

    env_spec_list[env_size - 1] = (env_spec *) NULL;
    env_spec_list[env_size - 2] = current_env;
    if (DEBUG) printf("DEBUG: initialized first env spec\n");

    //---------------------------------------------------------
    //---------------------------------------------------------
    //environment description
    //---------------------------------------------------------
    //read in environment specifications
    //---------------------------------------------------------
    if (strcmp(line,"EMPTY") != 0){
      //process environment specification
      //assume at least one line, and loop for next lines
      //using getc and ungetc to check for a sentinel*
      int spec_size = 1;
      current_env->environment = (char **) malloc(sizeof(char *) * ++spec_size);

      //handle initial line read in
      char * env_line = malloc(sizeof(char) * read + 1);
      strncpy(env_line,line,read + 1);

      current_env->environment[0] = env_line;
      current_env->environment[1] = (char *) NULL;
      if (DEBUG) printf("DEBUG: adding environment line %s\n",env_line);

      while (sentinel_check(config) == false) {
          read = getline(&line,&length,config);
          delete_newlines(line);
          if (read == 0) {
            if (DEBUG) printf("DEBUG: unexpected end of config\n");
            audit_log("DEBUG: unexpected end of config\n");
            silent_exit();
          }
          char * env_line = malloc(sizeof(char) * read + 1);
          strncpy(env_line,line,read + 1);
          if (DEBUG) printf("DEBUG: adding environment line %s\n",env_line);
          current_env->environment = (char **) realloc(current_env->environment,++spec_size * sizeof(char*));
          current_env->environment[env_size-1] = (char *) NULL;
          current_env->environment[env_size-2] = env_line;


      };
    } else {
      //else if the environment spec is empty
      if (DEBUG) printf("DEBUG: adding empty environment\n");
      current_env->environment = (char **) malloc(sizeof(char *) * 1);
      current_env->environment[0] = (char *) NULL;

      if (read == 0) {
        if (DEBUG) printf("DEBUG: unexpected end of config\n");
        audit_log("DEBUG: unexpected end of config\n");
        silent_exit();
      }
    }
    //get next line ready for command spec
    read = getline(&line,&length,config);
    delete_newlines(line);

    //---------------------------------------------------------
    //read in command specifications
    //---------------------------------------------------------

    //we shouldn't reach here if there aren't commands to be read
    if (line[0] != '*') {
      if (DEBUG) printf("DEBUG: expected command, got %s\n",line);
      //TODO: use sprintf to make this show the line
      audit_log("DEBUG: expected command");
      silent_exit();
    }

    //command specification
    //assume at least one first line, and loop
    //for additional lines using getc and ungetc
    //to verify sentinel *
    char * command;
    char * sha1sum;
    strtok(line," \t"); //ignore token
    command = strtok(NULL," \t");
    sha1sum = strtok(NULL," \t");

    int command_size = 1;
    current_env->full_commands = (char **) malloc(sizeof(char *) * ++command_size);
    current_env->sha1sums = (char **) malloc(sizeof(char *) * command_size);

    //handle initial line read in
    char * comm_dup = malloc(strlen(command) + 1);
    char * sha1_dup = malloc(strlen(sha1sum) + 1);
    strcpy(comm_dup,command);
    strcpy(sha1_dup,sha1sum);
    current_env->full_commands[0] = comm_dup;
    current_env->sha1sums[0] = sha1_dup;
    current_env->full_commands[1] = (char *) NULL;
    current_env->sha1sums[1] = (char *) NULL;
    if (DEBUG) printf("DEBUG: adding %s to environment with sha1sum %s\n",comm_dup,sha1_dup);

    do {
      read = getline(&line,&length,config);
      if (read == -1) break;
      delete_newlines(line);

      strtok(line," \t"); //ignore token
      command = strtok(NULL," \t");
      sha1sum = strtok(NULL," \t");

      current_env->full_commands = (char **) realloc(current_env->full_commands,++command_size * sizeof(char *));
      current_env->sha1sums = (char **) realloc(current_env->sha1sums,command_size * sizeof(char *));

      char * comm_dup = malloc(strlen(command) + 1);
      char * sha1_dup = malloc(strlen(sha1sum) + 1);
      strcpy(comm_dup,command);
      strcpy(sha1_dup,sha1sum);
      if (DEBUG) printf("DEBUG: adding %s to environment with sha1sum %s\n",comm_dup,sha1_dup);

      current_env->full_commands[command_size - 2] = comm_dup;
      current_env->sha1sums[command_size - 2] = sha1_dup;
      current_env->full_commands[command_size - 1] = (char *) NULL;
      current_env->sha1sums[command_size - 1] = (char *) NULL;

    } while (sentinel_check(config));
    //we have the fully qualified command names, but now we need to
    //find the regular command names.
    int i = -1;
    int count = 0;
    while (current_env->full_commands[++count] != (char *) NULL);
    current_env->commands = malloc(sizeof(char *) * (count + 1));
    current_env->commands[count] = (char *) NULL;
    while (current_env->full_commands[++i] != (char *) NULL) {
      char * last_slash = (char *) NULL;
      int j = -1;
      while (current_env->full_commands[i][++j]) {
          if (current_env->full_commands[i][j] == '/') last_slash = &(current_env->full_commands[i][j]);
      }
      if (last_slash == (char *) NULL) {
        if (DEBUG) printf("DEBUG: couldn't find command from qualified name\n");
        audit_log("DEBUG: couldn't find command from qualified name\n");
        silent_exit();
      }

      current_env->commands[i] = last_slash + 1;
      if (DEBUG) printf("DEBUG: added command %s\n",current_env->commands[i]);

    }
  }

}

void delete_newlines(char * line) {
  int i = -1;
  while (line[++i]) {
      if (line[i] == '\n') line[i] = '\0';
  }
}

bool sentinel_check(FILE * config) {
  int c;

  c = getc(config);
  ungetc(c,config);
  return (c == '*');

}

//--------------------------------------------
//borrowed from EVP.c
//with a few modifications
//must give fully qualified command name
bool cmp_sha1_sum(char * comm) {

  EVP_MD_CTX    mdctx;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  uint           md_len;
  int           i;
  struct stat   fileStat;
  int           fd;
  char          *buf;

       fd=open(comm,O_RDONLY);

       fstat(fd,&fileStat);
       buf=malloc(fileStat.st_size);
       read(fd,buf,fileStat.st_size);

       EVP_MD_CTX_init(&mdctx);

       EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);

       /* Demonstrate that we can do this in pieces */
       if (fileStat.st_size > 100){
            EVP_DigestUpdate(&mdctx, buf, 100);
            EVP_DigestUpdate(&mdctx, buf+100, fileStat.st_size-100);
         } else {
            EVP_DigestUpdate(&mdctx, buf, fileStat.st_size);
  }

       EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
       EVP_MD_CTX_cleanup(&mdctx);

       //printf("Digest is: ");
       //for(i = 0; i < md_len; i++) printf("%02x", md_value[i]);
       //printf("\n");
       char * sha1 = get_sha1_sum(comm);
       char sha1_buff[strlen(sha1)+1];
       char tmp[10];
       for (i = 0; i < 10; i++) tmp[i] = '\0';
       for (i = 0; i < strlen(sha1)+1; i++) sha1_buff[i] = '\0';
       for(i = 0; i < md_len; i++) {
         snprintf(tmp,9,"%02x",md_value[i]);
         strcat(sha1_buff,tmp);
       }

       return (strcmp(sha1_buff,sha1) != 0);

}

//setup the desired environment for a command
char ** getenvp(char * comm) {
  int i = -1;
  int j = -1;
  //swap with fully qualified command name
  comm = qualify_command(comm);
  if (comm == (char *) NULL) {
    if(DEBUG) printf("DEBUG: command not in config\n");

    return (char **) NULL;
  }

  while (env_spec_list[++i]) {
    j = -1;
    while (env_spec_list[i]->full_commands[++j]) {
        if (strcmp(comm,env_spec_list[i]->full_commands[j]) == 0) {
            return env_spec_list[i]->environment;
        }
    }
  }
  if(DEBUG) printf("DEBUG: command not in config\n");

  return (char **) NULL;
}

char * qualify_command(char * comm) {
  int i = -1;
  int j = -1;
  if (env_spec_list == NULL) return (char *) NULL;


  while (env_spec_list[++i]) {
    j = -1;
    while (env_spec_list[i]->full_commands[++j]) {
        if (strcmp(comm,env_spec_list[i]->full_commands[j]) == 0) {
            return env_spec_list[i]->full_commands[j];
        }
        if (strcmp(comm,env_spec_list[i]->commands[j]) == 0) {
            return env_spec_list[i]->full_commands[j];
        }
    }
  }

  return (char *) NULL;
}

char * get_sha1_sum(char * comm) {
  int i = -1;
  int j = -1;

  while (env_spec_list[++i]) {
    j = -1;
    while (env_spec_list[i]->full_commands[++j]) {
        if (strcmp(comm,env_spec_list[i]->full_commands[j]) == 0) {
            return env_spec_list[i]->sha1sums[j];
        }
    }
  }

  return (char *) NULL;
}

void exec_comm(char * line) {
  int isParent;
  int apipe[2];
  char * cmd[2][3];
  int i;

  isParent = fork();
  if (isParent) {
    int status = -1;
    wait(&status);
    return;
  }


  //#if command does not involve a pipe,
  //execute only one command
  i = -1;
  while (line[++i]) {
    if (line[i] == '|') break;
  }
  if (i == strlen(line)) {
    if (DEBUG) printf("DEBUG: executing only one command\n");
    //parse line by spaces
    cmd[0][0] = strtok(line," ");
    cmd[0][1] = strtok(NULL," ");
    cmd[0][2] = (char *) NULL;
    //convert commands to fully qualified commands
    cmd[0][0] = qualify_command(cmd[0][0]);
    if (cmd[0][0] == (char *) NULL) {
      printf("DEBUG: silent fail, command not in config\n");
      audit_log("command not in config\n");
      exit(0);
    }
    if (cmp_sha1_sum(cmd[0][0])) {
      printf("DEBUG: silent fail, invalid sha1\n");
      audit_log("invalid sha1\n");
      exit(0);
    }
    log_command(cmd[0][0]);
    execve(cmd[0][0],cmd[0],getenvp(cmd[0][0]));
    log_error(cmd[0][0]);
    exit(1);
  } else {
    if (DEBUG) printf("DEBUG: executing with a pipe\n");
  }

  //parse line into 2 by 3 array of
  //command, arguments and null
  char * comm1 = strtok(line,"|");
  char * comm2 = strtok(NULL,"|");
  cmd[0][0] = strtok(comm1," ");
  cmd[0][1] = strtok(NULL," ");
  cmd[0][2] = (char *) NULL;

  cmd[1][0] = strtok(comm2," ");
  cmd[1][1] = strtok(NULL," ");
  cmd[1][2] = (char *) NULL;

  //convert commands to fully qualified commands
  cmd[0][0] = qualify_command(cmd[0][0]);
  cmd[1][0] = qualify_command(cmd[1][0]);
  if (cmd[0][0] == (char *) NULL) {
    printf("DEBUG: silent fail, command not in config\n");
    audit_log("command not in config\n");
    exit(0);
  }
  if (cmd[1][0] == (char *) NULL) {
    printf("DEBUG: silent fail, command not in config\n");
    audit_log("command not in config\n");
    exit(0);
  }

  //else, pipe
  pipe(apipe);
  isParent = fork();
  if (!isParent) {
    // Want stdin connected to pipe
   	close(apipe[1]); // not writing to pipe write end

  	close(0); // close stdin (0 now available)
   	dup(apipe[0]); // dup read end to stdin (will use 0)
   	close(apipe[0]); // close old read end
     if (cmp_sha1_sum(cmd[0][0])) {
       printf("DEBUG: silent fail, invalid sha1\n");
       audit_log("invalid sha1\n");
       exit(0);
     }
     log_command(cmd[1][0]);
   	execve(cmd[1][0],cmd[1],getenvp(cmd[1][0])); // stdin now the pipe read end
     log_error(cmd[1][0]);
   	exit(1);
  } else {

    // Want stdout connected to pipe
   	close(apipe[0]); // not reading from pipe read end
   	close(1); // close stdout (1 now available)
   	dup(apipe[1]); // dup write end to stdout (will use 1)
   	close(apipe[1]); // close old write end
     if (cmp_sha1_sum(cmd[0][0])) {
       printf("DEBUG: silent fail, invalid sha1\n");
       audit_log("invalid sha1\n");
       exit(0);
     }
     log_command(cmd[0][0]);
   	execve(cmd[0][0],cmd[0],getenvp(cmd[0][0])); // stdout is pipe write end
    log_error(cmd[0][0]);
    exit(1);
  }

}

void log_error(char * comm) {
  size_t buff_length = 2000;
  char buff[buff_length];
  buff[0] = '\0';

  size_t length = 200;
  char tmp[length];
  //log name
  strcat(buff,"process failed for ");
  strcat(buff,comm);
  //log error
  strcat(buff,"error code: ");
  snprintf(tmp,length,"%d",errno);
  strcat(buff,",");
  //log time
  time_t current_time;
  char * time_str;
  current_time = time((time_t *) NULL);
  time_str = ctime(&current_time);
  delete_newlines(time_str);
  strcat(buff,",");
  strcat(buff,time_str);

  audit_log(buff);

}

void log_command(char * comm) {
  size_t buff_length = 2000;
  char buff[buff_length];
  buff[0] = '\0';
  size_t length = 200;
  char tmp[length];
  //log real and effective uid and gid
  strcat(buff,"real uid:");
  snprintf(tmp,length,"%d",getuid());
  strcat(buff,tmp);
  audit_log(" real gid:");
  snprintf(tmp,length,"%d",getgid());
  strcat(buff,tmp);
  strcat(buff," effective uid:");
  snprintf(tmp,length,"%d",geteuid());
  strcat(buff,tmp);
  strcat(buff," effective gid:");
  snprintf(tmp,length,"%d",getegid());
  strcat(buff,tmp);
  //log time
  time_t current_time;
  char * time_str;
  current_time = time((time_t *) NULL);
  time_str = ctime(&current_time);
  delete_newlines(time_str);
  strcat(buff,",");
  strcat(buff,time_str);

  //log terminal
  char * term;
  term = ctermid((char *) NULL);
  strcat(buff,",");
  strcat(buff,term);

  //log command
  strcat(buff,",");
  strcat(buff,comm);
  //log environment
  strcat(buff,",");
  char ** env = getenvp(comm);
  int i = -1;
  if (env != (char **) NULL) {
    while (env[++i]) {
      strcat(buff,env[i]);
      strcat(buff,":");
    }
  }

  strcat(buff,"\n");

  audit_log(buff);
}

void run() {
  //-------------------------------------------------------
  //Actual shell
  //-------------------------------------------------------
  char * line = NULL;
  size_t length = 0;
  ssize_t read;

  do {
    printf("<Shash> # ");
    read = getline(&line,&length,stdin);
    delete_newlines(line);
    if (read == -1) break;
    if (strcmp(line,"q") == 0) break;
    if (strcmp(line,"quit") == 0) break;
    audit_log("executing: ");
    audit_log(line);
    audit_log("\n");
    exec_comm(line);
    cleanup();

  } while (true);
  if (DEBUG) printf("DEBUG: shell terminating normally\n");
}
