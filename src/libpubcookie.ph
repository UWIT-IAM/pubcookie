if (!defined &PUBCOOKIE_LIB) {
    eval 'sub PUBCOOKIE_LIB () {1;}' unless defined(&PUBCOOKIE_LIB);
    require 'opensslv.ph';
    if ((defined(&OPENSSL_VERSION_NUMBER) ? &OPENSSL_VERSION_NUMBER : 0) < 0x00904000) {
	eval 'sub PRE_OPENSSL_094 () {1;}' unless defined(&PRE_OPENSSL_094);
    }
    if (defined &APACHE1_2) {
    }
    else {
	if (defined &APACHE1_3) {
	}
	else {
	}
    }
}
1;
