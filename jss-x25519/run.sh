#!/bin/sh

classpath="/usr/share/java/commons-lang.jar:/usr/share/java/commons-codec.jar:/usr/share/java/slf4j/slf4j-api.jar:/usr/share/java/slf4j/slf4j-jdk14.jar:/usr/share/java/jaxb-api.jar:/usr/lib/java/jss4.jar"
jsslibdir="/usr/lib64/jss"
jsslib="$jsslibdir/libjss4.so"

javac -cp "$classpath" TriggerClientHello.java && LD_LIBRARY_PATH="$jsslibdir" java -Djava.library.path="$jsslib" -cp "$classpath:." TriggerClientHello "$@"
