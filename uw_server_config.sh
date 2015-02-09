# configure command used by UW to build login server

./configure \
   --enable-login \
   --enable-krb5 \
   --disable-apache \
   --with-ssl=/usr/lib64 \
   --with-ezs=yes \
   --with-lsc=no \
   --with-mango-inc-dir=/tulsa/include \
   --with-mango-lib-dir=/tulsa/lib/rhel6 \
   --with-audit-log=LOG_LOCAL3 \
   --with-general-log=LOG_LOCAL3 \
   --enable-uwsecurid \
   --enable-autoupgrade

