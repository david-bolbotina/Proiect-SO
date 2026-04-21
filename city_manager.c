#include <stdio.h>
#include <string.h>
//director
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
//fisiere
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

    //argumente
    if (argc < 3) {
        printf("Usage: %s --role <inspector|manager> [command]\n", argv[0]);
        return 1;
    }

    //rol
    char *role = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[i + 1];
        }
    }

    if (role == NULL) {
        printf("Error: --role not specified\n");
        return 1;
    }

    if (strcmp(role, "inspector") != 0 && strcmp(role, "manager") != 0) {
        printf("Error: Invalid role\n");
        return 1;
    }


    //user
    char *user = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            user = argv[i + 1];
        }
    }

    if (user == NULL) {
        printf("Error: --user not specified\n");
        return 1;
    }

    //comenzi
    char *command = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--add") == 0 && i + 1 < argc) {
            command = "add";
            arg1 = argv[i + 1];
        }
        else if (strcmp(argv[i], "--remove_report") == 0 && i + 2 < argc) {
            command = "remove_report";
            arg1 = argv[i + 1];
            arg2 = argv[i + 2];
        }
    }

    if (command == NULL) {
        printf("Error: No valid command specified\n");
        return 1;
    } 



    if (strcmp(command, "add") == 0) {
        if (arg1 == NULL) {
            printf("Error: district not specified\n");
            return 1;
        }
        //permisiune 750
        if (mkdir(arg1, 0750) == -1) {
            //daca directorul exista deja, nu e o eroare
            if (errno != EEXIST) {
                perror("mkdir failed");
                return 1;
            }
            //seteaza permisiunea explicit, pentru cazul in care directorul exista deja
        }
        chmod(arg1, 0750);
        //buffer pentru path
        char path[256];
        //e.g. "district1/reports.dat"
        snprintf(path, sizeof(path), "%s/reports.dat", arg1);
        //creare fisier cu permisiune 664
        int fd = open(path, O_CREAT | O_RDWR, 0664);
        //daca fisierul exista deja, nu e o eroare
        if (fd == -1) {
            perror("open reports.dat");
            return 1;
        }
        //seteaza permisiunea explicit, pentru cazul in care fisierul exista deja
        chmod(path, 0664);
        close(fd);
        
        //aceeasi chestie si pentru restu
        snprintf(path, sizeof(path), "%s/district.cfg", arg1);

        fd = open(path, O_CREAT | O_RDWR, 0640);
        if (fd == -1) {
            perror("open district.cfg");
            return 1;
        }
        chmod(path, 0640);
        close(fd);

        snprintf(path, sizeof(path), "%s/logged_district", arg1);

        fd = open(path, O_CREAT | O_RDWR, 0644);
        if (fd == -1) {
            perror("open logged_district");
            return 1;
        }
        chmod(path, 0664);
        close(fd);
    }
    

    return 0;
}