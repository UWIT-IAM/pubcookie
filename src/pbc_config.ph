if (!defined &PUBCOOKIE_CONFIG) {
    eval 'sub PUBCOOKIE_CONFIG () {1;}' unless defined(&PUBCOOKIE_CONFIG);
    if (defined ( &APACHE1_2) || defined ( &APACHE1_3)) {
	eval 'sub APACHE () {1;}' unless defined(&APACHE);
    }
    eval 'sub PBC_L_COOKIENAME () {"pubcookie_l";}' unless defined(&PBC_L_COOKIENAME);
    eval 'sub PBC_G_COOKIENAME () {"pubcookie_g";}' unless defined(&PBC_G_COOKIENAME);
    eval 'sub PBC_S_COOKIENAME () {"pubcookie_s";}' unless defined(&PBC_S_COOKIENAME);
    eval 'sub PBC_AUTH_FAILED_HANDLER () {"pubcookie-failed-handler";}' unless defined(&PBC_AUTH_FAILED_HANDLER);
    eval 'sub PBC_BAD_USER_HANDLER () {"pubcookie-bad-user";}' unless defined(&PBC_BAD_USER_HANDLER);
    eval 'sub PBC_LOGIN_PAGE () {"https://pcookiel1.cac.washington.edu/login/get_pubcookie/index.cgi";}' unless defined(&PBC_LOGIN_PAGE);
    eval 'sub PBC_CRYPT_KEYFILE () {"/tmp/c_key";}' unless defined(&PBC_CRYPT_KEYFILE);
    eval 'sub PBC_DEFAULT_INACT_EXPIRE () {30* 60;}' unless defined(&PBC_DEFAULT_INACT_EXPIRE);
    eval 'sub PBC_DEFAULT_HARD_EXPIRE () {8* 60* 60;}' unless defined(&PBC_DEFAULT_HARD_EXPIRE);
    eval 'sub PBC_MAX_HARD_EXPIRE () {12* 60* 60;}' unless defined(&PBC_MAX_HARD_EXPIRE);
    eval 'sub PBC_DEFAULT_EXPIRE_LOGIN () {8* 60* 60;}' unless defined(&PBC_DEFAULT_EXPIRE_LOGIN);
    eval 'sub PBC_GRANTING_EXPIRE () {60;}' unless defined(&PBC_GRANTING_EXPIRE);
    eval 'sub PBC_BAD_AUTH () {1;}' unless defined(&PBC_BAD_AUTH);
    eval 'sub PBC_BAD_USER () {2;}' unless defined(&PBC_BAD_USER);
    eval 'sub PBC_FORCE_REAUTH () {3;}' unless defined(&PBC_FORCE_REAUTH);
    eval 'sub PBC_NUWNETID_AUTHTYPE () {"uwnetid";}' unless defined(&PBC_NUWNETID_AUTHTYPE);
    eval 'sub PBC_SECURID_AUTHTYPE () {"securid";}' unless defined(&PBC_SECURID_AUTHTYPE);
    eval 'sub PBC_REFRESH_TIME () {0;}' unless defined(&PBC_REFRESH_TIME);
    eval 'sub PBC_ENTRPRS_DOMAIN () {".washington.edu";}' unless defined(&PBC_ENTRPRS_DOMAIN);
    eval 'sub PBC_SIG_LEN () {128;}' unless defined(&PBC_SIG_LEN);
    eval 'sub PBC_CREDS_NONE () {ord(\'0\');}' unless defined(&PBC_CREDS_NONE);
    eval 'sub PBC_CREDS_UWNETID () {ord(\'1\');}' unless defined(&PBC_CREDS_UWNETID);
    eval 'sub PBC_CREDS_SECURID () {ord(\'2\');}' unless defined(&PBC_CREDS_SECURID);
    eval 'sub PBC_CREDS_MCIS () {ord(\'3\');}' unless defined(&PBC_CREDS_MCIS);
    eval 'sub PBC_COOKIE_TYPE_NONE () {ord(\'0\');}' unless defined(&PBC_COOKIE_TYPE_NONE);
    eval 'sub PBC_COOKIE_TYPE_G () {ord(\'1\');}' unless defined(&PBC_COOKIE_TYPE_G);
    eval 'sub PBC_COOKIE_TYPE_S () {ord(\'2\');}' unless defined(&PBC_COOKIE_TYPE_S);
    eval 'sub PBC_COOKIE_TYPE_L () {ord(\'3\');}' unless defined(&PBC_COOKIE_TYPE_L);
    eval 'sub PBC_L_CERTFILE () {"/usr/local/pubcookie/pubcookie_login.cert";}' unless defined(&PBC_L_CERTFILE);
    eval 'sub PBC_L_KEYFILE () {"/usr/local/pubcookie/pubcookie_login.key";}' unless defined(&PBC_L_KEYFILE);
    eval 'sub PBC_S_CERTFILE () {"/usr/local/pubcookie/pubcookie_session.cert";}' unless defined(&PBC_S_CERTFILE);
    eval 'sub PBC_S_KEYFILE () {"/usr/local/pubcookie/pubcookie_session.key";}' unless defined(&PBC_S_KEYFILE);
    eval 'sub PBC_G_CERTFILE () {"/tmp/pubcookie_granting.cert";}' unless defined(&PBC_G_CERTFILE);
    eval 'sub PBC_G_KEYFILE () {"/tmp/pubcookie_granting.key";}' unless defined(&PBC_G_KEYFILE);
    if (defined &APACHE1_2) {
	eval 'sub pbc_malloc {
	    local($x) = @_;
	    eval " &palloc( &p, $x)";
	}' unless defined(&pbc_malloc);
	eval 'sub pbc_strdup {
	    local($x) = @_;
	    eval " &pstrdup( &p, $x)";
	}' unless defined(&pbc_strdup);
	eval 'sub pbc_strndup {
	    local($s, $n) = @_;
	    eval " &pstrdup( &p, $s, $n)";
	}' unless defined(&pbc_strndup);
	eval 'sub pbc_fopen {
	    local($x, $y) = @_;
	    eval " &pfopen( &p, $x, $y)";
	}' unless defined(&pbc_fopen);
	eval 'sub pbc_fclose {
	    local($x) = @_;
	    eval " &pfclose( &p, $x)";
	}' unless defined(&pbc_fclose);
    }
    elsif ((defined(&APACHE1_3) ? &APACHE1_3 : 0)) {
	eval 'sub pbc_malloc {
	    local($x) = @_;
	    eval " &ap_palloc( &p, $x)";
	}' unless defined(&pbc_malloc);
	eval 'sub pbc_strdup {
	    local($x) = @_;
	    eval " &ap_pstrdup( &p, $x)";
	}' unless defined(&pbc_strdup);
	eval 'sub pbc_strndup {
	    local($s, $n) = @_;
	    eval " &ap_pstrdup( &p, $s, $n)";
	}' unless defined(&pbc_strndup);
	eval 'sub pbc_fopen {
	    local($x, $y) = @_;
	    eval " &ap_pfopen( &p, $x, $y)";
	}' unless defined(&pbc_fopen);
	eval 'sub pbc_fclose {
	    local($x) = @_;
	    eval " &ap_pfclose( &p, $x)";
	}' unless defined(&pbc_fclose);
    }
    if (!defined &pbc_malloc) {
	eval 'sub pbc_malloc {
	    local($x) = @_;
	    eval " &malloc($x)";
	}' unless defined(&pbc_malloc);
    }
    if (!defined &pbc_strdup) {
	eval 'sub pbc_strdup {
	    local($x) = @_;
	    eval " &strdup($x)";
	}' unless defined(&pbc_strdup);
    }
    if (!defined &pbc_strndup) {
	eval 'sub pbc_strndup {
	    local($s, $n) = @_;
	    eval " &strncpy( &calloc($n+1, $sizeof{\'char\'}), $s, $n)";
	}' unless defined(&pbc_strndup);
    }
    if (!defined &pbc_fopen) {
	eval 'sub pbc_fopen {
	    local($x, $y) = @_;
	    eval " &fopen($x, $y)";
	}' unless defined(&pbc_fopen);
    }
    if (!defined &pbc_fclose) {
	eval 'sub pbc_fclose {
	    local($x) = @_;
	    eval " &fclose($x)";
	}' unless defined(&pbc_fclose);
    }
    if (defined ( &APACHE1_2) || defined ( &APACHE1_3)) {
	eval 'sub libpbc_get_cookie {
	    local($a,$b,$c,$d,$e,$f,$g,$h) = @_;
	    eval " &libpbc_get_cookie_p( &p, $a,$b,$c,$d,$e,$f,$g,$h)";
	}' unless defined(&libpbc_get_cookie);
	eval 'sub libpbc_unbundle_cookie {
	    local($a,$b,$c) = @_;
	    eval " &libpbc_unbundle_cookie_p( &p, $a,$b,$c)";
	}' unless defined(&libpbc_unbundle_cookie);
	eval 'sub libpbc_update_lastts {
	    local($a,$b,$c) = @_;
	    eval " &libpbc_update_lastts_p( &p, $a,$b,$c)";
	}' unless defined(&libpbc_update_lastts);
	eval 'sub libpbc_sign_init {
	    local($a) = @_;
	    eval " &libpbc_sign_init_p( &p, $a)";
	}' unless defined(&libpbc_sign_init);
	eval 'sub libpbc_verify_init {
	    local($a) = @_;
	    eval " &libpbc_verify_init_p( &p, $a)";
	}' unless defined(&libpbc_verify_init);
	eval 'sub libpbc_pubcookie_init () {
	    eval " &libpbc_pubcookie_init_p( &p)";
	}' unless defined(&libpbc_pubcookie_init);
	eval 'sub libpbc_pubcookie_exit () {
	    eval " &libpbc_pubcookie_exit_p( &p)";
	}' unless defined(&libpbc_pubcookie_exit);
	eval 'sub libpbc_alloc_init {
	    local($a) = @_;
	    eval " &libpbc_alloc_init_p( &p, $a)";
	}' unless defined(&libpbc_alloc_init);
	eval 'sub libpbc_gethostip () {
	    eval " &libpbc_gethostip_p( &p)";
	}' unless defined(&libpbc_gethostip);
	eval 'sub libpbc_init_crypt {
	    local($a) = @_;
	    eval " &libpbc_init_crypt_p( &p, $a)";
	}' unless defined(&libpbc_init_crypt);
	eval 'sub libpbc_rand_malloc () {
	    eval " &libpbc_rand_malloc_p( &p)";
	}' unless defined(&libpbc_rand_malloc);
	eval 'sub libpbc_get_private_key {
	    local($a,$b) = @_;
	    eval " &libpbc_get_private_key_p( &p, $a,$b)";
	}' unless defined(&libpbc_get_private_key);
	eval 'sub libpbc_get_public_key {
	    local($a,$b) = @_;
	    eval " &libpbc_get_public_key_p( &p, $a,$b)";
	}' unless defined(&libpbc_get_public_key);
	eval 'sub libpbc_init_cookie_data () {
	    eval " &libpbc_init_cookie_data_p( &p)";
	}' unless defined(&libpbc_init_cookie_data);
	eval 'sub libpbc_init_md_context_plus () {
	    eval " &libpbc_init_md_context_plus_p( &p)";
	}' unless defined(&libpbc_init_md_context_plus);
	eval 'sub libpbc_get_crypt_key {
	    local($a,$b) = @_;
	    eval " &libpbc_get_crypt_key_p( &p, $a,$b)";
	}' unless defined(&libpbc_get_crypt_key);
	eval 'sub libpbc_sign_cookie {
	    local($a,$b) = @_;
	    eval " &libpbc_sign_cookie_p( &p, $a,$b)";
	}' unless defined(&libpbc_sign_cookie);
	eval 'sub libpbc_sign_bundle_cookie {
	    local($a,$b,$c) = @_;
	    eval " &libpbc_sign_bundle_cookie_p( &p, $a,$b,$c)";
	}' unless defined(&libpbc_sign_bundle_cookie);
	eval 'sub libpbc_stringify_cookie_data {
	    local($a) = @_;
	    eval " &libpbc_stringify_cookie_data_p( &p, $a)";
	}' unless defined(&libpbc_stringify_cookie_data);
    }
    else {
	eval 'sub libpbc_get_cookie {
	    local($a,$b,$c,$d,$e,$f,$g,$h) = @_;
	    eval " &libpbc_get_cookie_np($a,$b,$c,$d,$e,$f,$g,$h)";
	}' unless defined(&libpbc_get_cookie);
	eval 'sub libpbc_unbundle_cookie {
	    local($a,$b,$c) = @_;
	    eval " &libpbc_unbundle_cookie_np($a,$b,$c)";
	}' unless defined(&libpbc_unbundle_cookie);
	eval 'sub libpbc_update_lastts {
	    local($a,$b,$c) = @_;
	    eval " &libpbc_update_lastts_np($a,$b,$c)";
	}' unless defined(&libpbc_update_lastts);
	eval 'sub libpbc_sign_init {
	    local($a) = @_;
	    eval " &libpbc_sign_init_np($a)";
	}' unless defined(&libpbc_sign_init);
	eval 'sub libpbc_verify_init {
	    local($a) = @_;
	    eval " &libpbc_verify_init_np($a)";
	}' unless defined(&libpbc_verify_init);
	eval 'sub libpbc_pubcookie_init () { &libpbc_pubcookie_init_np;}' unless defined(&libpbc_pubcookie_init);
	eval 'sub libpbc_pubcookie_exit () { &libpbc_pubcookie_exit_np;}' unless defined(&libpbc_pubcookie_exit);
	eval 'sub libpbc_alloc_init {
	    local($a) = @_;
	    eval " &libpbc_alloc_init_np($a)";
	}' unless defined(&libpbc_alloc_init);
	eval 'sub libpbc_gethostip () { &libpbc_gethostip_np;}' unless defined(&libpbc_gethostip);
	eval 'sub libpbc_init_crypt {
	    local($a) = @_;
	    eval " &libpbc_init_crypt_np($a)";
	}' unless defined(&libpbc_init_crypt);
	eval 'sub libpbc_rand_malloc () { &libpbc_rand_malloc_np;}' unless defined(&libpbc_rand_malloc);
	eval 'sub libpbc_get_private_key {
	    local($a,$b) = @_;
	    eval " &libpbc_get_private_key_np($a,$b)";
	}' unless defined(&libpbc_get_private_key);
	eval 'sub libpbc_get_public_key {
	    local($a,$b) = @_;
	    eval " &libpbc_get_public_key_np($a,$b)";
	}' unless defined(&libpbc_get_public_key);
	eval 'sub libpbc_init_cookie_data () { &libpbc_init_cookie_data_np;}' unless defined(&libpbc_init_cookie_data);
	eval 'sub libpbc_init_md_context_plus () { &libpbc_init_md_context_plus_np;}' unless defined(&libpbc_init_md_context_plus);
	eval 'sub libpbc_get_crypt_key {
	    local($a,$b) = @_;
	    eval " &libpbc_get_crypt_key_np($a,$b)";
	}' unless defined(&libpbc_get_crypt_key);
	eval 'sub libpbc_sign_cookie {
	    local($a,$b) = @_;
	    eval " &libpbc_sign_cookie_np($a,$b)";
	}' unless defined(&libpbc_sign_cookie);
	eval 'sub libpbc_sign_bundle_cookie {
	    local($a,$b,$c) = @_;
	    eval " &libpbc_sign_bundle_cookie_np($a,$b,$c)";
	}' unless defined(&libpbc_sign_bundle_cookie);
	eval 'sub libpbc_stringify_cookie_data {
	    local($a) = @_;
	    eval " &libpbc_stringify_cookie_data_np($a)";
	}' unless defined(&libpbc_stringify_cookie_data);
    }
}
1;
