//shash.h
//monofuel
//CS 5950
#include <stdbool.h>
#include <stdio.h>

typedef struct {
  char ** environment;
  char ** commands;
  char ** full_commands;
  char ** sha1sums;

} env_spec;

void cleanup();
void load_config();
void run();
void audit_log(char *);
bool sentinel_check(FILE *);
void silent_exit();
void delete_newlines(char *);
char ** getenvp(char *);
bool cmp_sha1_sum(char *);
void log_error(char *);
void log_command(char *);
char * get_sha1_sum(char *);
char * qualify_command(char *);
void exec_comm(char *);
int main(int,char**);
