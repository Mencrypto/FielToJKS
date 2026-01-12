# Convierte FIEL a PFX (p12) o JKS

## Objetivo
El proyecto tiene como objetivo ser una utilería para transformar la Firma Electrónica (FIEL) que proporciona el SAT (Sistema de Administración Tributaría) de  México a partir del certificado y llave que proporciona a un keystore en pfx o jks, que puede servir en otro tipo de proyectos de firma digital.

## Uso
Se requiere indicar la ruta del archivo key y el archivo cer
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

## Descarga:

Requiere JDK 11.
[Link Pendiente](https://github.com/Mencrypto/FielToJKS/releases).

## Para dudas visita mi web:

[Mencrypto](https://mencrypto.com/).