
#ifndef _HEADER_H_
#define _HEADER_H_

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define DIM       4096
#define UNIMAX    4294967296.   /*pow(2,32)*/

typedef unsigned int    uniform;    

typedef unsigned long   counter;

typedef double          real;

uniform uni(char *filename);

double Phi(double z);

double Chisq(int df, double chsq);

double Poisson(double lambda, int k);

real KStest(real *x, int dim);

#endif /*_HEADER_H_*/



