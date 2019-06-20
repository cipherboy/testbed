#!/bin/sh

export CLASSPATH="/usr/share/java/slf4j/simple.jar:/usr/share/java/slf4j/api.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/apache-commons-lang.jar:/usr/share/java/jaxb-api.jar:/usr/lib/java/jss4.jar"

javac -classpath "$CLASSPATH" Reproducer.java && java -classpath "$CLASSPATH:." Reproducer "$@"
