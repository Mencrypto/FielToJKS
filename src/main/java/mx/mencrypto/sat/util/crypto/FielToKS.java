package mx.mencrypto.sat.util.crypto;

import java.io.Console;
import java.io.File;
import java.io.FilenameFilter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class FielToKS {

	public static void main(String[] args) {
		
		Options options = new Options();
		options.addOption("h", "help", false, "Ayuda");
        options.addOption("v", "version", false, "Versión");
        options.addOption("key", "key", true, "Ruta del archivo key, si no existe se intentará con el primer archivo .key que exista en el directorio");
        options.addOption("cer", "cer", true, "Ruta del archivo cer, si no existe se intentará con el primer archivo .cer que exista en el directorio");
        options.addOption("pwd", "password", true, "Contraseña de la FIEL, o la llave");
        options.addOption("jks", "jks", false, "Indica si se genera un archivo jks, por default generará un KeyStore en formato p12 (pfx)");
        // El password final es opcional pasarle un valor, si no tiene lo va a solicitar
	    Option option = new Option("pwdf", "passwordFinal", true, "Establece la contraseña del KeyStore generado, si no tiene valor será requerido");
	    option.setOptionalArg(true);
	    options.addOption(option);
        
        CommandLineParser parser = new DefaultParser(); 
        
        // Parámetros neecesarios
        String keyPath = null, certPath = null, password = null, passwordFinal = null;
        Boolean jks = false;
        
        @SuppressWarnings("deprecation")
		HelpFormatter formatter = new HelpFormatter();
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("h")) {
                formatter.printHelp("Forma de ejecución: ", options);
                return;
            }

            if (cmd.hasOption("v")) {
                System.out.println("Version 1.0.0");
                return;
            }
            
            if (cmd.hasOption("key")) {
                keyPath = cmd.getOptionValue("key");
                System.out.println("Llave: " + keyPath);
            }else {
            	keyPath = getLocalCertOrKey("key");
                if (keyPath == null) {
                	System.out.println("No se encontró ninguna llave use la opción -key $ruta para indicar la ruta en la que tiene la llave de la FIEL");
                	System.exit(1);
                }
            }
            
            if (cmd.hasOption("cer")) {
                certPath = cmd.getOptionValue("cer");
                System.out.println("Certificado: " + certPath);
            }else {
            	certPath = getLocalCertOrKey("cer");
                if (keyPath == null) {
                	System.out.println("No se encontró ningun certificado use la opción -cer $path para indicar la ruta en la que tiene el certificado de la FIEL");
                	System.exit(1);
                }
            }
            
            if (cmd.hasOption("jks")) {
                jks = true;
                System.out.println("Opción jks encontrada, se generará un archivo jks");
            }else {
            	System.out.println("Opción jks no encontrada, se generará un archivo p12");
            }
            
            if (cmd.hasOption("pwd")) {
                password = cmd.getOptionValue("pwd");
            }else {
            	System.out.println("Ingrese la contraseña de la FIEL");
            	Console console = System.console();
            	if (console == null) {
                    System.out.println("Error: No se puede obtener la consola. Asegúrate de ejecutar el programa desde una terminal");
                    System.exit(1);
                }
            	char[] passwordArray = console.readPassword("Contraseña: ");
                password = new String(passwordArray);
                if (password.length() < 1 || password.length() > 128) {
                	System.out.println("Error: La contraseña debe tener entre 1 y 128 caracteres");
                	System.exit(1);
                }
            }
            
            if (cmd.hasOption("pwdf")) {
                passwordFinal = cmd.getOptionValue("pwdf");
                if (passwordFinal == null || "".equals(passwordFinal)) {
	            	System.out.println("Ingrese la contraseña del KeyStore resultante entre 5 y 20 caracteres");
	            	Console console = System.console();
	            	if (console == null) {
	                    System.out.println("Error: No se puede obtener la consola. Asegúrate de ejecutar el programa desde una terminal");
	                    System.exit(1);
	                }
	            	char[] passwordArrayFinal = console.readPassword("Contraseña final: ");
	            	// Convertir el array de char a String
	                passwordFinal = new String(passwordArrayFinal);
	                if (passwordFinal.length() < 5 || passwordFinal.length() > 20) {
	                	System.out.println("Error: La contraseña debe tener entre 1 y 128 caracteres");
	                	System.exit(1);
	                }
                }
            }
        } catch (ParseException e) {
            System.out.println("Error de análisis de argumentos: " + e.getMessage());
            formatter.printHelp("Ejemplo CLI", options);
            System.exit(1);
        }

		File key = new File(keyPath);
		File certFile = new File(certPath);

		Boolean changePwd = passwordFinal != null || ! "".equals(passwordFinal);
		if(jks) {
			if(changePwd) {
				//Crea un JKS con una nueva password
				FIELConvertions.createJKSwithCertAndKey(key, certFile, password, passwordFinal);
			}else {
				//Crea un JKS con el mismo password de la FIEL
				FIELConvertions.createJKSwithCertAndKey(key, certFile, password);
			}	
		}else {
			if(changePwd) {
				//Crea un P12 con una nueva password
				FIELConvertions.createPKCS12withCertAndKey(key, certFile, password, passwordFinal);

			}else {
				//Crea un P12 con el mismo password de la FIEL
				FIELConvertions.createPKCS12withCertAndKey(key, certFile, password);
			}
		}
		
	}

	/**
	 * Obtiene el primer archivo con la extensión fileExtension que se le pasa
	 * útil para buscar el key y cer de la FIEL
	 * @param fileExtension extensión del archivo que se quiere buscar
	 * @return String con la ruta de un archivo encontrado
	 */
	private static String getLocalCertOrKey(String fileExtension) {
        String currentDirectory = System.getProperty("user.dir");
        System.out.println("Buscando archivo " + fileExtension +" en directorio actual: " + currentDirectory);
        File dir = new File(currentDirectory);
        FilenameFilter filter = (file, name) -> name.endsWith(fileExtension);
        File[] docFiles = dir.listFiles(filter);
        if (docFiles != null && docFiles.length > 0) {
        	return docFiles[0].getPath();
        } else {
            return null;
        }
	}
	
}
