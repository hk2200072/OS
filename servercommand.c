#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char **environ;

void show_environment() {
    for (char **env = environ; *env; env++) printf("%s\n", *env);
}

void list_dir(const char *path) {
    DIR *dir = opendir(path ? path : ".");
    if (!dir) return perror("opendir");
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] != '.') printf("%s ", entry->d_name);
    }
    printf("\n");
    closedir(dir);
}

void change_dir(const char *path) {
    char cwd[1024];
    if (!path) getcwd(cwd, sizeof(cwd));
    else chdir(path);
    if (getcwd(cwd, sizeof(cwd))) setenv("PWD", cwd, 1);
}

void shell_prompt(FILE *source) {
    char *line = NULL, *token, *args[64];
    size_t len = 0;
    while (1) {
        printf("/root%s> ", getenv("PWD"));
        if (getline(&line, &len, source) == -1) break;

        int i = 0, bg = 0, append = 0;
        char *infile = NULL, *outfile = NULL;

        token = strtok(line, " \n");
        while (token) {
            if (!strcmp(token, "<")) infile = strtok(NULL, " \n");
            else if (!strcmp(token, ">")) { outfile = strtok(NULL, " \n"); append = 0; }
            else if (!strcmp(token, ">>")) { outfile = strtok(NULL, " \n"); append = 1; }
            else if (!strcmp(token, "&")) bg = 1;
            else args[i++] = token;
            token = strtok(NULL, " \n");
        }
        args[i] = NULL;
        if (!args[0]) continue;

        // Output redirection
        FILE *old_stdout = NULL, *redir_out = NULL;
        if (outfile) {
            old_stdout = stdout;
            redir_out = freopen(outfile, append ? "a" : "w", stdout);
            if (!redir_out) perror("redirect fail");
        }

        // Built-in commands
        if (!strcmp(args[0], "ls") || !strcmp(args[0], "dir")) list_dir(args[1]);
        else if (!strcmp(args[0], "cd")) change_dir(args[1]);
        else if (!strcmp(args[0], "set") && args[1] && args[2]) setenv(args[1], args[2], 1);
        else if (!strcmp(args[0], "environ")) show_environment();
        else if (!strcmp(args[0], "echo")) for (int j = 1; args[j]; j++) printf("%s ", args[j]); printf("\n");
        else if (!strcmp(args[0], "pause")) { printf("Press Enter to continue..."); while (getchar() != '\n'); }
        else if (!strcmp(args[0], "help")) {
            printf("Commands:\nls [path], cd [path], set VAR VALUE, environ, echo [text], pause, exit, help\n");
        }
        else if (!strcmp(args[0], "exit")) {
            if (redir_out) { fflush(stdout); stdout = old_stdout; fclose(redir_out); }
            break;
        }
        else {
            pid_t pid = fork();
            if (pid == 0) {
                if (infile) freopen(infile, "r", stdin);
                if (outfile) freopen(outfile, append ? "a" : "w", stdout);
                execvp(args[0], args);
                perror("exec failed");
                exit(1);
            } else if (!bg) waitpid(pid, NULL, 0);
            else signal(SIGCHLD, SIG_IGN);
        }

        if (redir_out) { fflush(stdout); stdout = old_stdout; fclose(redir_out); }
    }
    free(line);
}

int main(int argc, char *argv[]) {
    FILE *input = argc > 1 ? fopen(argv[1], "r") : stdin;
    if (!input) return perror("file open failed"), 1;

    char *home = getenv("HOME");
    chdir(home ? home : "/");
    setenv("PWD", home ? home : "/", 1);

    shell_prompt(input);
    if (argc > 1) fclose(input);
    return 0;
}
