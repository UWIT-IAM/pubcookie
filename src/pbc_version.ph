if (!defined &PUBCOOKIE_VERSION) {
    eval 'sub PUBCOOKIE_VERSION () {1;}' unless defined(&PUBCOOKIE_VERSION);
    eval 'sub PBC_VERSION () {"a4";}' unless defined(&PBC_VERSION);
}
1;
