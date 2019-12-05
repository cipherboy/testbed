#!/bin/bash

export log="-Djava.security.debug=all -Djavax.net.debug=all"

javac -classpath "." SSLEngineSimpleDemo.java
java $log -classpath "." SSLEngineSimpleDemo
