if (!defined &PUBCOOKIE_LIB) {
    eval 'sub PUBCOOKIE_LIB () {1;}' unless defined(&PUBCOOKIE_LIB);
    if (defined ( &APACHE1_2) || defined ( &APACHE1_3)) {
    }
    else {
    }
}
1;
