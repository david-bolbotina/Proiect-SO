#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//director
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
//fisiere
#include <fcntl.h>
#include <unistd.h>
//lungimi; padding pentru reporturi, etc
#define NAME_LEN 50
#define CATEGORY_LEN 20
#define DESC_LEN 100
//timestamp pt report file
#include <time.h>

typedef struct {
    int id;
    int severity;

    float latitude;
    float longitude;

    time_t timestamp;

    char inspector[NAME_LEN];
    char category[CATEGORY_LEN];
    char description[DESC_LEN];

}Report;


void print_permissions(mode_t mode) {
    char perms[10];

    perms[0] = (mode & S_IRUSR) ? 'r' : '-';
    perms[1] = (mode & S_IWUSR) ? 'w' : '-';
    perms[2] = (mode & S_IXUSR) ? 'x' : '-';

    perms[3] = (mode & S_IRGRP) ? 'r' : '-';
    perms[4] = (mode & S_IWGRP) ? 'w' : '-';
    perms[5] = (mode & S_IXGRP) ? 'x' : '-';

    perms[6] = (mode & S_IROTH) ? 'r' : '-';
    perms[7] = (mode & S_IWOTH) ? 'w' : '-';
    perms[8] = (mode & S_IXOTH) ? 'x' : '-';

    perms[9] = '\0';

    printf("Permissions: %s\n", perms);
}

void log_action(const char *district, const char *role, const char *user, const char *action) {
    char path[256];
    snprintf(path, sizeof(path), "%s/logged_district", district);

    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd == -1) {
        perror("open log file");
        return;
    }

    time_t now = time(NULL);

    char buffer[512];
    int len = snprintf(buffer, sizeof(buffer),
        "[%ld] role=%s user=%s action=%s district=%s\n",
        now, role, user, action, district
    );

    if (write(fd, buffer, len) != len) {
        perror("write log failed");
    }

    close(fd);
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    const char *p1 = strchr(input, ':');
    if (!p1) return 0;

    const char *p2 = strchr(p1 + 1, ':');
    if (!p2) return 0;

    // extract field
    size_t len_field = p1 - input;
    strncpy(field, input, len_field);
    field[len_field] = '\0';

    // extract operator
    size_t len_op = p2 - (p1 + 1);
    strncpy(op, p1 + 1, len_op);
    op[len_op] = '\0';

    // extract value
    strcpy(value, p2 + 1);

    return 1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {

    // ---- severity (int) ----
    if (strcmp(field, "severity") == 0) {
        int val = atoi(value);

        if (strcmp(op, "==") == 0) return r->severity == val;
        if (strcmp(op, "!=") == 0) return r->severity != val;
        if (strcmp(op, "<")  == 0) return r->severity < val;
        if (strcmp(op, "<=") == 0) return r->severity <= val;
        if (strcmp(op, ">")  == 0) return r->severity > val;
        if (strcmp(op, ">=") == 0) return r->severity >= val;
    }

    // ---- category (string) ----
    else if (strcmp(field, "category") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->category, value) != 0;
    }

    // ---- inspector (string) ----
    else if (strcmp(field, "inspector") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->inspector, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->inspector, value) != 0;
    }

    // ---- timestamp (time_t) ----
    else if (strcmp(field, "timestamp") == 0) {
        time_t val = (time_t)atol(value);

        if (strcmp(op, "==") == 0) return r->timestamp == val;
        if (strcmp(op, "!=") == 0) return r->timestamp != val;
        if (strcmp(op, "<")  == 0) return r->timestamp < val;
        if (strcmp(op, "<=") == 0) return r->timestamp <= val;
        if (strcmp(op, ">")  == 0) return r->timestamp > val;
        if (strcmp(op, ">=") == 0) return r->timestamp >= val;
    }

    return 0; // unknown field or operator
}

int main(int argc, char *argv[]) {

    //argumente
    if (argc < 5) {
        printf("Usage: %s --role <inspector|manager> --user <username> --[command]\n", argv[0]);
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
    //pentru filter
    char *conditions[10];
    int condition_count = 0;
    int filter_index = -1;

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
        else if (strcmp(argv[i], "--list") == 0 && i + 1 < argc) {
            command = "list";
            arg1 = argv[i + 1];
        }
        else if (strcmp(argv[i], "--view") == 0 && i + 2 < argc) {
        command = "view";
            arg1 = argv[i + 1];
            arg2 = argv[i + 2];
        }
        else if (strcmp(argv[i], "--update_threshold") == 0 && i + 2 < argc) {
            command = "update_threshold";
            arg1 = argv[i + 1];
            arg2 = argv[i + 2];
        }
        else if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            command = "filter";
            arg1 = argv[i + 1];
            filter_index = i;
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
        }
        //seteaza permisiunea explicit, pentru cazul in care directorul exista deja
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
        chmod(path, 0644);
        close(fd);


       
        snprintf(path, sizeof(path), "%s/reports.dat", arg1);

        fd = open(path, O_RDWR | O_APPEND);
        if (fd == -1) {
            perror("open reports.dat");
            return 1;
        }
        //calculeaza id-ul urmatorului report; pentru asta, folosim lseek pentru a afla dimensiunea fisierului
        off_t size = lseek(fd, 0, SEEK_END);    
        if (size == -1) {
            perror("lseek failed");
            close(fd);
            return 1;
        }
        
        //logica id; citim toate reporturile din fisier pentru a gasi id-ul maxim, apoi adaugam 1 pentru noul report
        int max_id = 0;
        Report temp;

        // go to start of file
        if (lseek(fd, 0, SEEK_SET) == -1) {
            perror("lseek failed");
            close(fd);
            return 1;
        }

        while (1) {
            ssize_t bytes = read(fd, &temp, sizeof(Report));

            if (bytes == 0) break;

            if (bytes < 0) {
                perror("read failed");
                close(fd);
                return 1;
            }

            if (bytes != sizeof(Report)) {
                printf("Corrupted record\n");
                close(fd);
                return 1;
            }

            if (temp.id > max_id) {
                max_id = temp.id;
            }
        }

        int next_id = max_id + 1;

        //lseek inapoi la sfarsitul fisierului pentru a adauga noul report
        if (lseek(fd, 0, SEEK_END) == -1) {
            perror("lseek end failed");
            close(fd);
            return 1;
        }

        printf("Next report ID: %d\n", next_id);
        //initializam cu 0 pentru a evita garbage data in padding
        Report r = {0};

        r.id = next_id;

        printf("X: ");
        scanf("%f", &r.latitude);

        printf("Y: ");
        scanf("%f", &r.longitude);

        //consuma newline-ul ramas in buffer dupa scanf
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        printf("Category: ");
        fgets(r.category, CATEGORY_LEN, stdin);
        r.category[strcspn(r.category, "\n")] = '\0';

        printf("Severity level (1-3): ");
        scanf("%d", &r.severity);
        if (r.severity < 1 || r.severity > 3) {
            printf("Invalid severity\n");
            close(fd);
            return 1;
        }

        while ((c = getchar()) != '\n' && c != EOF);

        printf("Enter description: ");
        fgets(r.description, DESC_LEN, stdin);
        r.description[strcspn(r.description, "\n")] = '\0';

        strncpy(r.inspector, user, NAME_LEN);
        r.inspector[NAME_LEN - 1] = '\0';

        r.timestamp = time(NULL);

        if (write(fd, &r, sizeof(Report)) != sizeof(Report)) {
            perror("write failed");
            close(fd);
            return 1;
        }
        
        log_action(arg1, role, user, "add");
        close(fd);
    }

    if(strcmp(command, "list") == 0) {
        if(arg1 == NULL) {
            printf("Error: district not specified\n");
            return 1;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s/reports.dat", arg1);

        int fd = open(path, O_RDONLY);
        if(fd == -1) {
            perror("open reports.dat");
            return 1;
        }

        Report r;
        while (1) {
            ssize_t bytes = read(fd, &r, sizeof(Report));

            if (bytes == 0) {
                // end of file
                break;
            }

            if (bytes < 0) {
                perror("read failed");
                close(fd);
                return 1;
            }

            if (bytes != sizeof(Report)) {
                printf("Partial read error\n");
                close(fd);
                return 1;
            }

            printf("ID: %d\n", r.id);
            printf("Inspector: %s\n", r.inspector);
            printf("Location: (%f, %f)\n", r.latitude, r.longitude);
            printf("Category: %s\n", r.category);
            printf("Severity: %d\n", r.severity);
            printf("Timestamp: %ld\n", r.timestamp);
            printf("Description: %s\n", r.description);
            printf("-----------------------------\n");

        }
        
        //trebuie comentat mai tarziu
        struct stat st;

        if (stat(path, &st) == -1) {
            perror("stat failed");
            close(fd);
            return 1;
        }

        printf("\n=== File Info ===\n");

        print_permissions(st.st_mode);

        printf("Size: %ld bytes\n", st.st_size);
        printf("Last modified: %ld\n", st.st_mtime);

        log_action(arg1, role, user, "list");
        close(fd);

    }

    if (strcmp(command, "view") == 0) {
        if (arg1 == NULL || arg2 == NULL) {
            printf("Error: missing arguments\n");
            return 1;
        }

        int id = atoi(arg2);
        if (id <= 0) {
            printf("Invalid report ID\n");
            return 1;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s/reports.dat", arg1);

        int fd = open(path, O_RDONLY);
        if (fd == -1) {
            perror("open reports.dat");
            return 1;
        }
        

        Report r;
        int found = 0;

        //citim toate reporturile pentru a gasi pe cel cu id-ul dat; nu putem face lseek direct la offset pentru ca id-urile nu sunt garantat consecutive (daca s-au sters rapoarte)
        while (1) {
            ssize_t bytes = read(fd, &r, sizeof(Report));

            if (bytes == 0) break;

            if (bytes < 0) {
                perror("read failed");
                close(fd);
                return 1;
            }

            if (bytes != sizeof(Report)) {
                printf("Corrupted record\n");
                close(fd);
                return 1;
            }

            if (r.id == id) {
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("Report not found\n");
            close(fd);
            return 1;
        }

        printf("ID: %d\n", r.id);
        printf("Inspector: %s\n", r.inspector);
        printf("Location: (%f, %f)\n", r.latitude, r.longitude);
        printf("Category: %s\n", r.category);
        printf("Severity: %d\n", r.severity);
        printf("Timestamp: %ld\n", r.timestamp);
        printf("Description: %s\n", r.description);

        log_action(arg1, role, user, "view");
        close(fd);
    }

    if (strcmp(command, "remove_report") == 0) {
        if (strcmp(role, "manager") != 0) {
            printf("Permission denied: only manager can remove reports\n");
            return 1;
        }

        if (arg1 == NULL || arg2 == NULL) {
            printf("Error: missing arguments\n");
            return 1;
        }

        int id = atoi(arg2);
        if (id <= 0) {
            printf("Invalid report ID\n");
            return 1;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s/reports.dat", arg1);

        int fd = open(path, O_RDWR);
        if (fd == -1) {
            perror("open reports.dat");
            return 1;
        }

        Report r;
        int index = -1;
        int current_index = 0;

        if (lseek(fd, 0, SEEK_SET) == -1) {
            perror("lseek failed");
            close(fd);
            return 1;
        }

        //citim toate reporturile pentru a gasi indexul celui cu id-ul dat; avem nevoie de index pentru a face shift left
        while (1) {
            ssize_t bytes = read(fd, &r, sizeof(Report));

            if (bytes == 0) break;

            if (bytes < 0) {
                perror("read failed");
                close(fd);
                return 1;
            }

            if (bytes != sizeof(Report)) {
                printf("Corrupted record\n");
                close(fd);
                return 1;
            }

            if (r.id == id) {
                index = current_index;
                break;
            }

            current_index++;
        }

        if (index == -1) {
            printf("Report not found\n");
            close(fd);
            return 1;
        }


        off_t size = lseek(fd, 0, SEEK_END);
        if (size == -1) {
            perror("lseek failed");
            close(fd);
            return 1;
        }

        int total = size / sizeof(Report);


        //shift left pentru a suprascrie reportul cu id-ul dat; 
        for (int i = index + 1; i < total; i++) {
            //citeste reportul de la pozitia i
            off_t read_pos = i * sizeof(Report);
            if (lseek(fd, read_pos, SEEK_SET) == -1) {
                perror("lseek read");
                close(fd);
                return 1;
            }

            if (read(fd, &r, sizeof(Report)) != sizeof(Report)) {
                perror("read failed");
                close(fd);
                return 1;
            }

            // scrie reportul la pozitia i-1
            off_t write_pos = (i - 1) * sizeof(Report);
            if (lseek(fd, write_pos, SEEK_SET) == -1) {
                perror("lseek write");
                close(fd);
                return 1;
            }

            if (write(fd, &r, sizeof(Report)) != sizeof(Report)) {
                perror("write failed");
                close(fd);
                return 1;
            }
        }

        //trunchiaza fisierul pentru a elimina ultimul report, care e acum duplicat
        off_t new_size = (total - 1) * sizeof(Report);

        if (ftruncate(fd, new_size) == -1) {
            perror("ftruncate failed");
            close(fd);
            return 1;
        }

        log_action(arg1, role, user, "remove_report");
        close(fd);
    }

    if (strcmp(command, "update_threshold") == 0) {
        if (strcmp(role, "manager") != 0) {
            printf("Permission denied: only manager can update threshold\n");
            return 1;
        }

        if (arg1 == NULL || arg2 == NULL) {
            printf("Error: missing arguments\n");
            return 1;
        }

        int value = atoi(arg2);

        if (value < 1 || value > 3) {
            printf("Invalid threshold (must be 1–3)\n");
            return 1;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s/district.cfg", arg1);

        struct stat st;

        if (stat(path, &st) == -1) {
            perror("stat failed");
            return 1;
        }
        
        //masca 0777 pentru a obtine doar permisiunile, fara bitii de tip fisier sau alte atribute
        mode_t perms = st.st_mode & 0777;

        if (perms != 0640) {
            printf("Error: district.cfg permissions are incorrect\n", perms);
            return 1;
        }

        int fd = open(path, O_WRONLY | O_TRUNC);
        if (fd == -1) {
            perror("open district.cfg");
            return 1;
        }

        char buffer[10];
        int len = snprintf(buffer, sizeof(buffer), "%d\n", value);

        if (write(fd, buffer, len) != len) {
            perror("write failed");
            close(fd);
            return 1;
        }

        log_action(arg1, role, user, "update_threshold");
        close(fd);
    }

    if (strcmp(command, "filter") == 0) {
        for (int i = filter_index + 2; i < argc; i++) {
            conditions[condition_count++] = argv[i];
        }

        if (arg1 == NULL) {
            printf("Error: district not specified\n");
            return 1;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s/reports.dat", arg1);

        int fd = open(path, O_RDONLY);
        if (fd == -1) {
            perror("open reports.dat");
            return 1;
        }

        Report r;

        while (1) {
            ssize_t bytes = read(fd, &r, sizeof(Report));

            if (bytes == 0) break;

            if (bytes < 0) {
                perror("read failed");
                close(fd);
                return 1;
            }

            if (bytes != sizeof(Report)) {
                printf("Corrupted record\n");
                close(fd);
                return 1;
            }

            // reset match PER REPORT
            int match = 1;

            for (int i = 0; i < condition_count; i++) {
                char field[50], op[10], value[100];

                if (!parse_condition(conditions[i], field, op, value)) {
                    printf("Invalid condition: %s\n", conditions[i]);
                    match = 0;
                    break;
                }

                if (!match_condition(&r, field, op, value)) {
                    match = 0;
                    break;
                }
            }

            if (match) {
                printf("ID: %d\n", r.id);
                printf("Inspector: %s\n", r.inspector);
                printf("Location: (%f, %f)\n", r.latitude, r.longitude);
                printf("Category: %s\n", r.category);
                printf("Severity: %d\n", r.severity);
                printf("Timestamp: %ld\n", r.timestamp);
                printf("Description: %s\n", r.description);
                printf("-----------------------------\n");
            }
        }

        close(fd);
    }
    return 0;
}