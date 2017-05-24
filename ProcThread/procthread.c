/* This code is part of an exercise pack on Operating Systems for the needs of my Postgraduate course on CS */
/* The implementation is based on http://computing.unn.ac.uk/staff/cgmb3/teaching/threads/ */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

 

int x = 50; /* a global variable */
const clock_t MAXDELAY = 2900000;

/* A delay function for the output */ 

void delay(clock_t ticks) { 
 clock_t start = clock();
 do
 ; while (clock() < start + ticks);
}


/* A function which changes the number of a global variable  */ 
/* Refers to processes */

void change_number(char * kind, int i) {
   while (1)  /* loop forever */
   {   printf("%s: %i\n", kind, x);
       x += i;
       delay(rand()%MAXDELAY);
   }
}

/* adjustX changes the number of a global variable by a certain step */
/* Refers to threads */

void * adjustX(void *n) {
   int i = (int)n;
   while (1)   /* loop forever */
    {   printf("Thread adjustment = %2i; x = %i\n", i, x);
        x += i;
        delay(rand()%MAXDELAY);
   }
   return(n);
}


main() {  
   int a, c, n;
   srand(time(NULL));
   pthread_t  up_thread, dn_thread;
   pthread_attr_t *attr;  /* thread attribute variable */
   attr=0;  
   
   printf("Give adjustment: "); 
   scanf("%d" , &n); /* The user inserts the adjustment value for the treads */
   printf("creating  new process:\n");
   
   c = fork();
   printf("process %i created\n", c);
   if (c==0) {
      
      printf("creating threads:\n");
      pthread_create(&up_thread,attr, adjustX, (void *)n);
      pthread_create(&dn_thread,attr, adjustX, (void *)-n);
      change_number("child", 2);   /* child process */
      
      
      }	
   else 
      change_number("parent", -1);  /* parent process */

}
