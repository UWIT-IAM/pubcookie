hostname                                                             > Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
date /T                                                             >> Test_login_blob.out
time /T                                                             >> Test_login_blob.out
echo --------------------------------------------------------------->> Test_login_blob.out
ipconfig /all                                                       >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
echo System Root = %systemroot%                                     >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
echo dir %systemroot%\system32\inetsrv\Pubcookie\c_key              >> Test_login_blob.out
dir %systemroot%\system32\inetsrv\Pubcookie\c_key                   >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
cacls.exe %systemroot%\system32\inetsrv\pubcookie\c_key             >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
ssleay.exe md5  %systemroot%\system32\inetsrv\pubcookie\c_key       >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
echo dir login_blob                                                 >> Test_login_blob.out
dir login_blob                                                      >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
check_crypted_blob.exe -c login_blob                                >> Test_login_blob.out
echo -------------------------------------------------------------- >> Test_login_blob.out
