# Convierte FIEL a PFX (p12) o JKS

## Objetivo
El proyecto es una utilería para transformar la Firma Electrónica (FIEL) que proporciona el SAT (Sistema de Administración Tributaría) de  México a partir del certificado y llave que proporciona a un keystore en pfx o jks, que puede servir en otro tipo de proyectos de firma digital.

## Uso
Se requiere indicar la ruta del archivo *key* y el archivo *cer*
```
java -jar FielToKS.jar -key C:\ruta\NombreCertificado.key -cer C:\ruta\NombreLlave.cer
```
## Parámetros 
* key [opcional]: Ruta del archivo key, si no se le proporciona la opción, se intentará con un archivo .key que exista en el directorio.

* cer [opcional]: Ruta del archivo cer, si no se le proporciona la opción, se intentará con un  archivo .cer que exista en el directorio.

* pwd [opcional]: Contraseña de la FIEL, o la llave, si no se proporciona en el comando, será solicitada por la consola.

* pwdf [opcional]: Establece la contraseña del KeyStore resultante, si no tiene valor será requerido por la consola.

* **jks**: Indica si se genera un archivo jks, por default generará un KeyStore en formato p12 (pfx).

## Uso en el código:

Existe 4 métodos principales, su diferencia rádica en si el resultado es un JKS, un PFX y si la contraseña final del KeyStore es el mismo que la de la llave de la FIEL o uno distinto:


Crea un JKS con el mismo password de la FIEL

```
FIELConvertions.createJKSwithCertAndKey(key, certFile, password);
```

Crea un JKS con una nueva password
```
FIELConvertions.createJKSwithCertAndKey(key, certFile, password, passwordFinal);
```

Crea un P12 con el mismo password de la FIEL

```
FIELConvertions.createPKCS12withCertAndKey(key, certFile, password);
```

Crea un P12 con una nueva password
				
```
FIELConvertions.createPKCS12withCertAndKey(key, certFile, password, passwordFinal);
```

# Descarga:

Requiere JDK 11.

[Descarga Jar ejecutable](https://github.com/Mencrypto/FielToJKS/releases).


# Ejecutable para Windows
Para generar una imagen con el runtime necesario se debe usar el path de OpenJDK 17 por lo cual establecemos su ruta `en windows`:
```
set JAVA_HOME=D:\Temporales\jdk-17
set PATH=%JAVA_HOME%\bin;%PATH%
```
Empaquetamos:
```
mvn clean package
```
Se genera en la carpeta target el archivo `fieltojks-x.x.x.jar` donde `x.x.x` es la versión y que debes remplazar en los subsecuentes comandos.

Copia el archivo `fieltojks-x.x.x.jar` en una carpeta llamada `jarsPath` junto con los jars de los que depende:
```
bcprov-jdk18on-1.82.jar
bcpkix-jdk18on-1.82.jar
bcutil-jdk18on-1.82.jar
commons-cli-1.11.0.jar
```
Nota: se ocupa *bcutil* como una dependencia heredada que se puede consultar con `mvn dependency:tree`


Debemos ejecutar desde un **directorio arriba** de la carpeta `jarsPath` la herramienta **jlink** : 
```
jlink.exe --module-path "jmods;jarsPath" --add-modules com.mencrypto.sat.util.crypto --launcher FielToKS=com.mencrypto.sat.util.crypto/com.mencrypto.sat.util.crypto.FielToKS  --ignore-signing-information --output runtime
```
Lo anterior genera una carpeta especificada en el parámetro *output*, es decir *runtime*.

Para generar un paquete instalable con el nombre especificado en el parámetro *name* usaremos **jpackage** con el nombre de la carpeta de salida anterior.

Para usar jpackage en windows, debes instalar Wix 3:

[Página de descarga WiX 3](https://github.com/wixtoolset/wix3/releases)

Al ejecutar el comando de *jpackage* recuerda cambiar la versión de la aplicación en el jar y en el parámetro de *app-version*
```
jpackage --type exe --name FielToKS --input jarsPath --main-jar fieltojks-x.x.x.jar --main-class com.mencrypto.sat.util.crypto.FielToKS  --runtime-image runtime --dest dist --app-version x.x.x --description "Utilería para transformar la Firma Electrónica (FIEL) que proporciona el SAT (Sistema de Administración Tributaría) de México a partir del certificado y llave que proporciona a un keystore en pfx o jks, que puede servir en otro tipo de proyectos de firma digital" --win-console
```

Como resultado se tendrá una carpeta llamada *dist* y dentro un ejecutable:
`FielToKS-x.x.x.exe`

Al ejecutarlo se instalará en la ruta:
`C:\Program Files\FielToKS\FielToKS.exe`

Desde ahi puedes abrir una consola cmd de windows, y ejecutarlo de  la siguinte forma
```
FielToKS.exe [options]
```
Por ejemplo:
```
FielToKS.jar -key C:\ruta\NombreCertificado.key -cer C:\ruta\NombreLlave.cer
```

## Para dudas visita mi web:

[Mencrypto](https://mencrypto.com/)