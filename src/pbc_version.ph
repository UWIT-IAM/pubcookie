if (!defined &PUBCOOKIE_VERSION) {
    eval 'sub PUBCOOKIE_VERSION () {1;}' unless defined(&PUBCOOKIE_VERSION);
    eval 'sub PBC_VERSION () {"a5";}' unless defined(&PBC_VERSION);
    eval 'sub PBC_TESTID () {"release3";}' unless defined(&PBC_TESTID);
}
1;
