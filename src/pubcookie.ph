if (!defined &PUBCOOKIE_MAIN) {
    eval 'sub PUBCOOKIE_MAIN () {1;}' unless defined(&PUBCOOKIE_MAIN);
    require 'opensslv.ph';
    if ((defined(&OPENSSL_VERSION_NUMBER) ? &OPENSSL_VERSION_NUMBER : 0) < 0x00904000) {
	eval 'sub PRE_OPENSSL_094 () {1;}' unless defined(&PRE_OPENSSL_094);
    }
    eval 'sub PBC_USER_LEN () {42;}' unless defined(&PBC_USER_LEN);
    eval 'sub PBC_VER_LEN () {4;}' unless defined(&PBC_VER_LEN);
    eval 'sub PBC_APPSRV_ID_LEN () {40;}' unless defined(&PBC_APPSRV_ID_LEN);
    eval 'sub PBC_APP_ID_LEN () {128;}' unless defined(&PBC_APP_ID_LEN);
    eval 'sub PBC_TOT_COOKIE_DATA () {228;}' unless defined(&PBC_TOT_COOKIE_DATA);
    eval 'sub PBC_DES_KEY_BUF () {2048;}' unless defined(&PBC_DES_KEY_BUF);
    eval 'sub PBC_4K () {4096;}' unless defined(&PBC_4K);
    eval 'sub PBC_1K () {1024;}' unless defined(&PBC_1K);
    eval 'sub PBC_RAND_MALLOC_BYTES () {8;}' unless defined(&PBC_RAND_MALLOC_BYTES);
    eval 'sub PBC_X_STRING () {"XXXXXXXXXXXXX";}' unless defined(&PBC_X_STRING);
    eval 'sub PBC_XS_IN_X_STRING () {13;}' unless defined(&PBC_XS_IN_X_STRING);
    eval 'sub PBC_X_CHAR () {ord(\'X\');}' unless defined(&PBC_X_CHAR);
    eval 'sub PBC_NO_FORCE_REAUTH () {"NFR";}' unless defined(&PBC_NO_FORCE_REAUTH);
    eval 'sub PBC_INIT_IVEC () {{0x4c,0x43,0x5f,0x98,0xbc,0xab,0xef,0xca};}' unless defined(&PBC_INIT_IVEC);
    eval 'sub PBC_INIT_IVEC_LEN () {8;}' unless defined(&PBC_INIT_IVEC_LEN);
    eval 'sub PBC_DES_INDEX_FOLDER () {30;}' unless defined(&PBC_DES_INDEX_FOLDER);
}
1;
