#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct shop_info{
    char *name;
    int networth;
};

struct shop_garbage{
    char arr[100]; //this is a array to add things (max 100)
    struct shop_info *shop_s;
};

char *get_garbage_things(struct shop_garbage *shop_g,char *gar_);

int main(){
    struct shop_garbage *set_shop_info;

    set_shop_info->shop_s->name = "my shop"; //set name of the shop
    set_shop_info->shop_s->networth = 1000; //set networth of that

    char *input_garbage;
    printf("Enter your garbage to continue : ");
    scanf("%s",&input_garbage);

    char *getgar,*getvar,*getarr = get_garbage_things(&set_shop_info,&input_garbage);
    printf("%s\n",getgar);
    printf("%s\n",getvar);
    printf("%s\n",getarr);
}

char *get_garbage_things(struct shop_garbage *shop_g,char *gar_){
    shop_g->arr[0] = gar_;
    return shop_g->shop_s->name,shop_g->shop_s->networth,shop_g->arr[0];
}