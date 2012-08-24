#!/usr/bin/python

__author__ = "Nicolas Seriot"
__date__ = "2010-03-01"
__license__ = "GPL"

import os
import re
import shutil
import sys
import tempfile

def verified_macho_path(args):
    if len(sys.argv) != 2:
        return None

    path = sys.argv[1]

    if not os.path.isfile(path):
        return None

    ## Apparently there is a bug in otool -- it doesn't seem to like executables
    ## with spaces in the names. If this is the case, make a copy and analyze that.
    if ' ' in os.path.basename(path):
        ## don't remove the spaces, that could lead to an empty string
        new_filename = path.replace(' ', '_')
        new_path = os.path.join(tempfile.mkdtemp(), new_filename)
        shutil.copy(path, new_path)
        path = new_path

    cmd = "/usr/bin/file -b %r" % path
    s = os.popen(cmd).read()

    if not s.startswith('Mach-O'):
        return None
    
    return path

def signature_cmp(m1, m2):
    cls1 = m1[2:].split(' ')[0]
    cls2 = m2[2:].split(' ')[0]
    
    result = cmp(cls1, cls2)

    if result == 0: # same class
        if m1.startswith('+') and m2.startswith('-'):
            return -1
        elif m1.startswith('-') and m2.startswith('+'):
            return +1
        else: # same sign
            return cmp(m1, m2)
    
    return result

def implemented_methods(path):
    """
    returns {'sel1':[sig1, sig2], 'sel2':[sig3]}
    """
    
    re_sig_sel_ios = re.compile("\s*imp 0x\w+ ([+|-]\[.+\s(.+)\])")
    re_sig_sel_mac = re.compile("\s*imp ([+|-]\[.+\s(.+)\])")
    
    impl = {} # sel -> clsmtd
    
    for line in os.popen("/usr/bin/otool -oV %s" % path).xreadlines():
        results = re_sig_sel_ios.findall(line)
        if not results:
            results = re_sig_sel_mac.findall(line)
        #print results
        
        if not results:
            continue
        (sig, sel) = results[0]
        
        if sel in impl:
            impl[sel].append(sig)
        else:
            impl[sel] = [sig]
    
    return impl

def referenced_selectors(path):
    
    re_sel = re.compile("__TEXT:__objc_methname:(.+)")
    
    refs = set()
    
    lines = os.popen("/usr/bin/otool -v -s __DATA __objc_selrefs %s" % path).readlines() # ios & mac

    for line in lines:
        results = re_sel.findall(line)
        if results:
            refs.add(results[0])
    
    return refs

def potentially_unreferenced_methods():
    implemented = implemented_methods(path)
    
    if not implemented:
        print "# can't find implemented methods"
        sys.exit(1)
    
    referenced = referenced_selectors(path)
    
    l = []
    
    #print "-- implemented:", len(implemented)
    #print "-- referenced:", len(referenced)

    for sel in implemented:
        if sel not in referenced:
            for method in implemented[sel]:
                l.append(method)
                
    l.sort(signature_cmp)
    
    return l

if __name__ == "__main__":
    
    path = verified_macho_path(sys.argv)
    if not path:
        print "Usage: %s MACH_O_FILE" % sys.argv[0]
        sys.exit(1)
    
    methods = potentially_unreferenced_methods()
        
    print "# the following methods may be unreferenced"
    for m in methods:
        print m
