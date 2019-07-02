#!/bin/bash

# export CLASSPATH="/usr/share/java/slf4j/simple.jar:/usr/share/java/slf4j/api.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/apache-commons-lang.jar:/usr/share/java/jaxb-api.jar:/usr/lib/java/jss4.jar"
export CLASSPATH="/home/cipherboy/GitHub/cipherboy/jss/build/jss4.jar:/usr/share/java/slf4j/api.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/apache-commons-lang.jar:/usr/share/java/jaxb-api.jar:/usr/share/java/slf4j/jdk14.jar:/usr/share/java/junit.jar:/usr/share/java/hamcrest/core.jar"

# export log=""
export log="-Djava.util.logging.config.file=/home/cipherboy/GitHub/cipherboy/testbed/java-sslengine/logging.properties -Djavax.net.debug=all"

javac -classpath "$CLASSPATH:." SSLEngineSimpleDemo.java
gdb --args java $log -classpath "$CLASSPATH:." SSLEngineSimpleDemo
