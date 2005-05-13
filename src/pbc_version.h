/* ========================================================================
 * Copyright 2005 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/*
    $Id: pbc_version.h,v 1.71 2005-05-13 22:07:20 dors Exp $
 */

#ifndef PUBCOOKIE_VERSION
#define PUBCOOKIE_VERSION

/* The cookie version - Needs to stick around a while
   we can call this the protocol version.  it's what goes into the 
   current cookie or post messages.  might use the PBC_VERSION_MAJOR
   someday but this works for now.
 */
#define PBC_VERSION "a5"

/*
 * Someday the cookie version will be the major version or something like that.
 */

#define PBC_VERSION_MAJOR "3"
#define PBC_VERSION_MINOR "2"
#define PBC_VERSION_PATCH "1"

/* beta or final, so the code knows what it is, should it care. */
#define PBC_VERSION_RELEASE "beta"

/*
 * Please note that if you change the version string here, you should change it
 * in configure.ac and re-run autoconf and autoheader.
 * This is _exactly_ the same as PACKAGE_VERSION in configure.  At some point
 * configure should probably set this.
 */

#define PBC_VERSION_STRING "3.2.1 beta1"

#endif /* !PUBCOOKIE_VERSION */
