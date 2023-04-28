#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

bool Compare_strings(const char *arr1, const char *arr2);
long Load_level(char *level); // if loading was not  successful, returns -1
long Load_param(char *param); // if loading was not  successful, returns -1
bool Rule1(const char *pw);
bool Rule2(const char *pw, long param);
bool Rule3(const char *pw, int len, long param);
bool Rule4(const char *pw, int len, long param);
int Count_dif_chars (const bool *n_chars);
void error(int  err_num);
bool Length_Exceeded(int len);

// enum of error codes used in method void error(int err_num)
enum errcodes {
    ERR_LEN_EXCEEDED = 0,
    ERR_LEVEL_NOT_INT = 1,
    ERR_LEVEL_NOT_IN_RANGE = 2,
    ERR_PARAM_NOT_INT = 3,
    ERR_PARAM_NOT_IN_RANGE = 4,
    ERR_WRONG_ARGV = 5,
};

// struct made for calculating average length of passwords
typedef struct {
    int len_sum;
    int len_count;
} Avarege_len;


// struct made for holding stats data
typedef struct {
    bool n_chars[128];
    int min_len;
    Avarege_len avg_len;
} Stats;



int main(int argc, char *argv[]) {

//    constant variables used in the program
    const int PW_MAX_LEN = 101;         // length of pw = 100, but last char is always '\n' so PW_MAX_LEN must be set to 101
    const int LEVEL_POS = 1;
    const int PARAM_POS = 2;
    const int STATS_POSS = 3;
    const int ARGC_WITHOUT_STATS = 3;
    const int ARGC_WITH_STATS = 4;

//    if argc is shorter than 3, return error
    if (argc < 3) {
        error(ERR_WRONG_ARGV);
        return 1;
    }

//    sets const values of commands
    const long level = Load_level(argv[LEVEL_POS]);
    const long param = Load_param(argv[PARAM_POS]);
    const bool do_stats = Compare_strings(argv[STATS_POSS], "--stats") ? true : false;

//    if level or param were set to -1, returns error and stops program
    if (level == -1)
        return 1;
    if (param == -1)
        return 1;

//    returns error if argc is not in expected length
    if (!(argc == ARGC_WITHOUT_STATS || (argc == ARGC_WITH_STATS && do_stats == true))) {
        error(ERR_WRONG_ARGV);
        return 1;
    }

//    creates Stats struct
    Stats stats;
    for (int i = 0; i < 128; ++i) { stats.n_chars[i] = false; }
    stats.min_len = PW_MAX_LEN;
    stats.avg_len.len_count = 0;
    stats.avg_len.len_sum = 0;

//    starts to load in input
    while (true) {

        char pw[PW_MAX_LEN];
        int len = 0;

//        checks whether the new char is not EOF, if it is it breaks the loading
        if ((pw[len] = (char) getchar()) != EOF) {

//            keeps loading in new chars until it meets End of line ('\n')
            while (pw[len] != '\n') {

                len++;

//                checks whether the length of the current password was not exceeded
                if (Length_Exceeded(len)) {
                    error(ERR_LEN_EXCEEDED);
                    return 1;
                }

                pw[len] = (char) getchar();
            }

//            sets char '\n' to '\0'
            pw[len] = '\0';

//         if the new char is EOF, it breaks the loading
        } else {
            break;
        }

//        uses switch to go through the levels of security for password - starts from the highest and drops to the lowest,
//        if it dropped through all levels, than it is by default written on STDOUT,
//        else the switch is broken
//        (comments "// ...", "// fall through" needed to handle to falling through without error)
        switch (level) {
            case 4:
                // ...
                if (Rule4(pw, len, param) == false)
                    break;
                // fall through
            case 3:
                // ...
                if (Rule3(pw, len, param) == false)
                    break;
                // fall through
            case 2:
                // ...
                if (Rule2(pw, param) == false)
                    break;
                // fall through
            case 1:
                // ...
                if (Rule1(pw) == false)
                    break;
                // fall through
            default:
                printf("%s\n", pw);
                break;
        }

//        if do_stats is set to true, the stats are updated by the new password
        if (do_stats == true) {
            for (int i = 0; i < len; i++) {
                stats.n_chars[(int) pw[i]] = true;
            }
            stats.min_len = stats.min_len > len ? len : stats.min_len;
            stats.avg_len.len_sum += len;
            stats.avg_len.len_count++;
        }

    }

//    if do_stats is set to true, the stats are written on STDOUT
    if (do_stats == true) {
        printf("Statistika:\n"
               "Ruznych znaku: %d\n"
               "Minimalni delka: %d\n"
               "Prumerna delka: %.1f\n"
                , Count_dif_chars(stats.n_chars)
                , stats.min_len
                , (float) stats.avg_len.len_sum / (float) stats.avg_len.len_count);
    }


    return 0;
}

int Count_dif_chars (const bool *n_chars) {
    int count = 0;
    for (int i = 0; i < 128; i++) {
        if (n_chars[i] == true)
            count++;
    }
    return count;
}

bool Length_Exceeded(int len) {
    if (len > 100) {
        return true;
    }
    return false;
}

bool Rule1(const char *pw) {
    bool upper = false;
    bool lower = false;
    for (int i = 0; pw[i] != '\0'; i++) {
        if (pw[i] >= 'A' && pw[i] <= 'Z')
            upper = true;
        if (pw[i] >= 'a' && pw[i] <= 'z')
            lower = true;
    }
    return upper && lower;
}

bool Rule2(const char *pw, long param) {
    if (param > 4)
        param = 4;

    int lower = 0;
    int upper = 0;
    int num = 0;
    int specialChars = 0;


    for (int i = 0; pw[i] != '\0'; i++) {

        if (pw[i] >= 'a' && pw[i] <= 'z')
            lower = 1;

        if (pw[i] >= 'A' && pw[i] <= 'Z')
            upper = 1;

        if (pw[i] >= '0' && pw[i] <= '9')
            num = 1;

        if (pw[i] >= 32 && pw[i] <= 126 &&
            !(pw[i] >= 'a' && pw[i] <= 'z') &&
            !(pw[i] >= 'A' && pw[i] <= 'Z') &&
            !(pw[i] >= '0' && pw[i] <= '9'))
            specialChars = 1;

    }

    if (lower + upper + num + specialChars >= param)
        return true;
    else
        return false;
}

bool Rule3(const char *pw, int len, long param) {
    if (param >= len + 1)
        return true;

    bool seql = true;
    for (int i = 0; i <= len - param; i++) {
        seql = true;
        for (int j = 0; j < param; j++) {
            if (pw[i] != pw[i + j]) {
                seql = false;
                break;
            }
        }
        if (seql)
            return false;
    }
    return true;
}

bool Rule4(const char *pw, int len, long param) {
    if (param - 1 >= len)
        return true;

    bool equals = true;

    for (int i = 0; i < len - param; ++i) {
        for (int j = i + 1; j < len - param + 1; ++j) {
            equals = true;
            for (int k = 0; k < param; ++k) {
                if (pw[i + k] != pw[j + k]) {
                    equals = false;
                    break;
                }
            }
            if (equals)
                return false;
        }
    }
    return true;
}

// if loading was not  successful, returns -1
long Load_level(char *level) {
    long i;
    char *scrap;
    i = strtol(level, &scrap, 10);
    if (scrap[0] != '\0') {
        error(ERR_LEVEL_NOT_INT);
        return -1;
    }
    if (i <= 0 || i > 4) {
        error(ERR_LEVEL_NOT_IN_RANGE);
        return -1;
    }
    return i;
}

// if loading was not  successful, returns -1
long Load_param(char *param) {
    long i;
    char *scrap;
    i = strtol(param, &scrap, 10);
    if (scrap[0] != '\0') {
        error(ERR_PARAM_NOT_INT);
        return -1;
    }
    if (i <= 0) {
        error(ERR_PARAM_NOT_IN_RANGE);
        return -1;
    }
    return i;
}

bool Compare_strings(const char *arr1, const char *arr2) {
    if (arr1 == NULL)
        return false;
    int i = 0;
    while (arr1[i] != '\0' || arr2[i] != '\0') {
        if  (arr1[i] == '\0' && arr2[i] != '0')
            return false;
        if  (arr1[i] != '\0' && arr2[i] == '0')
            return false;
        if (arr1[i] != arr2[i])
            return false;
        i++;
    }
    return true;
}

void error(int err_num) {
    static  const  char *p[]  = {
            "Delka hesla vetsi jak 100.",           // err 0
            "Level neni cislo.",                    // err 1
            "Level neni v mnozine {1, 2, 3, 4}.",   // err 2
            "Param neni cislo.",                    // err 3
            "Param neni cele kladne cislo.",        // err 4
            "Spatne zadan vstupni prikaz."          // err 5
    };
    fprintf(stderr, "%s\n",p[err_num]);
}



