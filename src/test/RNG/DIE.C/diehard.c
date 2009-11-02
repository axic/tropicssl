
#include "header.h"
#include "macro.h"

void do_test(char *fn)
{
  int i, status[16], tmp, id, flag=0, order=0;
  char c;

  for(i=0; i<16; ++i){
    status[i]=0;
  }

  while( (c=getchar())!='\n' ){
    if( c==' ' ) continue;

    ungetc( c, stdin );
    scanf("%d", &tmp);

    ++order;
    if(tmp>0){
      id=tmp-1;
      flag=status[id]=order;
    }
    else{
      id=-tmp-1;
      status[id]=-order;
    }
  }

  if(order==0) return;

  if(flag<order && status[15]!=-order){
    status[15]=flag+1;
  }  
       
  if(status[15]>0){
    for(i=0; i<15; ++i){
      if( ABS(status[i])<status[15] && status[i]<=0){
        ++order;
        status[i]=order;
      }
    }
  }

  status[15]=1000;
  do{
    tmp=15;

    for(id=0; id<15; ++id){
      if(status[id]<=0){
        continue;
      }
   
      if(status[tmp]>status[id]){
        tmp=id;
        continue;
      }
    }    

    switch(tmp+1){
      case 1: bday(fn); break;
      case 2: operm5(fn); break;  
      case 3: binrnk(fn,"31x31"); binrnk(fn,"32x32"); break;
      case 4: binrnk(fn,"6x8"); break;   
      case 5: bitst(fn); break;
      case 6: monky(fn, "OPSO"); monky(fn, "OQSO"); monky(fn, "DNA"); break;
      case 7: cnt1s(fn, "stream"); break;
      case 8: cnt1s(fn, "specific"); break;   
      case 9: park(fn); break;
      case 10: mindist(fn); break; 
      case 11: sphere(fn); break;
      case 12: squeez(fn); break;
      case 13: osum(fn); break;
      case 14: runtest(fn); break;
      case 15: craptest(fn); break;
      default: break;
    }
   
    status[tmp]=0;
  }while(tmp!=15);

  return;
}

void diehard()
{

  char c, fn[100];


  puts("\n\t\t\t\tNOTE\n");

  puts("\tMost of the tests in DIEHARD return a p-value, which");
  puts("\tshould be uniform on [0,1) if the input file contains truly");
  puts("\tindependent random bits.   Those p-values are obtained by");
  puts("\tp=1-F(X), where F is the assumed distribution of the sample");
  puts("\trandom variable X---often normal. But that assumed F is often just");
  puts("\tan asymptotic approximation, for which the fit will be worst");
  puts("\tin the tails. Thus you should not be surprised with  occasion-");
  puts("\tal p-values near 0 or 1, such as .0012 or .9983. When a bit");
  puts("\tstream really FAILS BIG, you will get p`s of 0 or 1 to six ");
  puts("\tor more places.  By all means, do not, as a Statistician ");
  puts("\tmight, think that a p < .025 or p> .975 means that the RNG");
  puts("\thas \"failed the test at the .05 level\".  Such p`s happen");
  puts("\tamong the hundreds that DIEHARD produces, even with good RNGs.");
  puts("\t So keep in mind that \"p happens\"\n");
  puts("\tEnter the name of the file to be tested.");
  puts("\tThis must be a form=\"unformatted\",access=\"direct\" binary");
  puts("\tfile of about 10-12 million bytes. Enter file name: \n");

  while((c=getchar())==' ') ;

  if(c=='\n'){
    return;
  }

  ungetc(c, stdin);

  fgets(fn, sizeof(fn)-1, stdin);

  puts("\n\t\tHERE ARE YOUR CHOICES:\n");
  puts("\t\t1   Birthday Spacings");
  puts("\t\t2   Overlapping Permutations");
  puts("\t\t3   Ranks of 31x31 and 32x32 matrices");
  puts("\t\t4   Ranks of 6x8 Matrices");
  puts("\t\t5   Monkey Tests on 20-bit Words");
  puts("\t\t6   Monkey Tests OPSO,OQSO,DNA");
  puts("\t\t7   Count the 1`s in a Stream of Bytes");
  puts("\t\t8   Count the 1`s in Specific Bytes");
  puts("\t\t9   Parking Lot Test");
  puts("\t\t10  Minimum Distance Test");
  puts("\t\t11  Random Spheres Test");
  puts("\t\t12  The Sqeeze Test");
  puts("\t\t13  Overlapping Sums Test");
  puts("\t\t14  Runs Test");
  puts("\t\t15  The Craps Test");
  puts("\t\t16  All of the above\n");

  puts("\tTo choose any particular tests, enter corresponding numbers.");
  puts("\tEnter 16 for all tests. If you want to perform all but a few");
  puts("\ttests, enter corresponding numbers preceded by \"-\" sign.");
  puts("\tTests are executed in the order they are entered.\n");
  puts("\tEnter your choices.");

  do_test(fn);

   return;
}


main()
{
  diehard();

   return;
}
