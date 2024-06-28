#include<stdio.h>
#include<string.h>

//create some custom functions

int add_students(char firstname[40],char lastname[40]);
/**
 * int add_students(char firstname[40],char lastname[40])
 * This function add the students adta to the seperate file to store it.
 * file_name has 40 buffer and char with buffer(string) data type
 * last_name has same in first_name var
*/
char *List_students();
/**
 * it's used to get all students
 * its return how many students are in.
*/
int add_student(char firstname[40],char lastname[40]);
//this function is used to add students details.
int check_record_state(FILE *file);
//It checks file condition:
/**
 * if the file contains some contents,this function object it
 * even if its empty it return that mentioned(clear).
*/


//Initialize garbages.
struct garbage
{
    unsigned int state; //for functions resturnable result
    int students_count; // for students
};

/**
 * Below data structure for studenst data for fetch each data for each students 
 * respectively.
*/
struct std
{
    char firstname[40];
    char lastname[40];
};


int main(){
    struct std student;
    //make dashboard 
    printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    printf("\nSCHOOL MANAGEMENT SYSTEM\n");
    printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    printf("\n");
    printf("1.Add students\n");
    printf("2.List all students\n");
    printf("3.Remove students\n");
    printf("4.Check file state\n");
    printf("\n");

    while(1){
        int choice; // Init the choice counter
        printf("Enter the choice to continue: ");
        scanf("%d",&choice);

    if(choice > 4 || choice < 1){
        printf("Please enter correct choice to continue");
    } else if(choice == 1){
        int del_count;
        struct garbage g;
        g.students_count = 1;

        printf("How many students you want to add: ");
        scanf("%d",&del_count);

        for(int i = 0;i < del_count;i++,g.students_count++){
            printf("\nEnter first name of student %d to add: ",g.students_count);
            scanf("%s",student.firstname);
            printf("\nEnter last name of student %d to add: ",g.students_count);
            scanf("%s",student.lastname);
            

            if(add_students(student.firstname,student.lastname) == 1){
                printf("\nData added successfully\n");
            } else {
                printf("\nData failed to add\n");
            }
        }
    } else if(choice == 2){
        List_students();
    } else if(choice == 3){
        int del_count;
        struct garbage g;
        printf("How many students you want to add: ");
        scanf("%d",&del_count);

        for(int i = 0;i < del_count;i++,g.students_count++){
            printf("\nEnter first name of student %d: ",g.students_count);
            scanf("%s",student.firstname);
            printf("\nEnter last name of student %d: ",g.students_count);
            scanf("%s",student.lastname);
            

            if(add_student(student.firstname,student.lastname) == 1){
                printf("\nData addd successfully\n");
            } else {
                printf("\nData has been failed to addd\n");
            }
        }
    } else if(choice == 4){
        FILE * data;
        data = fopen("student.list","r");
        if(check_record_state(data)==1){
            printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
            printf("        CLEARED              ");
            printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
        } else {
            printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
            printf("        APPEARED             ");
            printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
        }
    }
    
}
}

int add_students(char firstname[40],char lastname[40]){
    struct garbage g;
    g.state = 0;
    FILE * data;
    data = fopen("student.list","a+");
    
    while(1){
        fprintf(data,"%s %s\n",firstname,lastname);
        g.state = 1;
        break;
    }
    return g.state;
    fclose(data);
}

char *List_students(){
    struct garbage g;
    g.state = 0;
    FILE *data;
    char getfile[100];
    data = fopen("student.list","r");
    char *m;
    
    //make dashboard 
    printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    printf("    STUDENTS RECORDS       ");
    printf("\n=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    printf("\n");
    while(m = fgets(getfile,100,data)){
        printf("  %s\n",m);
    }
    printf("=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    fclose(data);
}

int add_student(char firstname[40],char lastname[40]){
    struct garbage g;
    g.state = 0;
    FILE *data;
    data = fopen("student.list","r+");
   
    if(fputs("",data)){
        g.state = 1;
    } else {
        g.state = 0;
    }

    return g.state;
}

int check_record_state(FILE *file){
    struct garbage g;
    g.state = 0;
    if(file == NULL){
        g.state = 1;
    } else {
        g.state = 0;
    }
    return g.state;
}