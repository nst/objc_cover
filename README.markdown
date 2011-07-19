Say you have this Objective-C code:

    - (void)notUsed {
    	return;
    }

    - (void)actuallyUsed {
    	return;
    }

    // ...
    
    [self actuallyUsed];

Thanks to `/usr/bin/otool`, you can get clues about potentially unused methods, like this:

    $ python objc_cover.py /Users/nst/Desktop/iCalReport 
    # the following methods may be unreferenced
    -[MyClass notUsed]

The idea was [put first](http://lists.apple.com/archives/objc-language/2009/Oct/msg00085.html) by "Luke the Hiesterman" on the Apple Objective-C list.
