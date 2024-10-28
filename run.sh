#!/usr/bin/env bash

# Diese Datei soll Ihre Programm innerhalb des Containers ausführen und je nach
# Aufgabe eine Datei mit dem Ergebnis erzeugen. Der Name der Datei ist in der
# Aufgabe angegeben, aber oftmals solution.txt oder solution.[andere Dateiendung].

# Beachten Sie in jedem Fall die Option "-v $(pwd):/app/".
# Die sorgt dafür, dass das aktuelle Verzeichnis in den Container gemountet wird.
# Ansonsten können Sie keine Dateien im Container erzeugen, die außerhalb sichtbar sind.

# Bei der Ausführung gibt es 2 Alternativen.

# Entweder erfolgt der Aufruf über die Kommandozeile
docker run --rm -v "$(pwd)":/app/ cryptology cryptology

# oder es wird das ausgeführt, was im Dockerfile unter CMD eingetragen ist
# docker run --rm -v "$(pwd)":/app/ docker-crypto-gruppe-xx

