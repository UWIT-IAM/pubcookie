hostname                                                             > Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
date /T                                                             >> Test_local_blob.out
time /T                                                             >> Test_local_blob.out
echo --------------------------------------------------------------->> Test_local_blob.out
ipconfig /all                                                       >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
echo System Root = %systemroot%                                     >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
echo dir %systemroot%\system32\inetsrv\Pubcookie\c_key              >> Test_local_blob.out
dir %systemroot%\system32\inetsrv\Pubcookie\c_key                   >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
cacls.exe %systemroot%\system32\inetsrv\pubcookie\c_key             >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
ssleay.exe md5  %systemroot%\system32\inetsrv\pubcookie\c_key       >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
echo make_crypted_blob.exe  -o local_blob                           >> Test_local_blob.out
make_crypted_blob.exe  -o local_blob                                >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
echo dir local_blob                                                 >> Test_local_blob.out
dir local_blob                                                      >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
check_crypted_blob.exe -c local_blob                                >> Test_local_blob.out
echo -------------------------------------------------------------- >> Test_local_blob.out
