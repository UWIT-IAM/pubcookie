

Tests:

candv - creates a signed cookie, updates the last timestamp,  and then breaks 
        it up and verifys it.  basically a create and a verify stuck together.  

dtest - just tests the des encrypt stuff, if candv works then this should.

Misc debugging:

ERR_print_errors_fp(stdout) will cycle throught the ssleay errors
and give you some information.

