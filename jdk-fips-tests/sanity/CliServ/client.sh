#!/bin/bash

export classpath="/usr/share/java/httpcomponents/httpclient.jar:/usr/share/java/commons-logging.jar:/usr/share/java/httpcomponents/httpcore.jar:/usr/share/java/httpcomponents/httpcore-nio.jar:."

export flags="-Djava.security.debug=all -Djavax.net.debug=all"

javac -classpath "$classpath" Client.java && java -classpath "$classpath" -Dcom.redhat.fips=true $flags Client TLS
