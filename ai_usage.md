I used ChatGPT, this was my prompt:

I am implementing a C program in a Unix environment that manages structured “city inspection reports” stored in a binary file. I only need help generating two helper functions related to filtering.

You don't need my full program, just generate these two functions cleanly in C.

Each report is stored as a fixed-size struct, like so:

typedef struct {
    int id;
    int severity;              // integer: 1 (low), 2 (medium), 3 (high)
    
    float latitude;
    float longitude;
    
    time_t timestamp;
    
    char inspector[50];
    char category[20];        // e.g. "road", "lighting", "flooding"
    char description[100];
    
} Report;

The program supports filtering reports using conditions of the form "field:operator:value", like so:
severity:>=:2
category:==:road
inspector:!=:alice
timestamp:<:1710000000

The fields' types go as follows: severity -> int, category -> string, inspector -> string, timestamp -> time_t.

Context aside, here's what I'd like you to implement precisely:

First off, implement the following function

int parse_condition(const char *input, char *field, char *op, char *value);

The function splits a string of the form"field:op:value", stores each part into the provided buffers, returns 1 on success and 0 on failure (like invalid format).

Second, please implement this function:

int match_condition(Report *r, const char *field, const char *op, const char *value);

The function evaluates whether a report satisfies a condition, converts types appropriately (int, string, time_t), supports all the operations I listed above and similarily, returns 1 on match and 0 otherwise.	

Please don't use any external libraries, so just standard C and don't allocate dynamically.

---

These are the functions that the AI gave as output:

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