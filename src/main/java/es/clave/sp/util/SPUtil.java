package es.clave.sp.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import es.clave.sp.ApplicationContextProvider;
import es.clave.sp.ApplicationSpecificServiceException;
import es.clave.sp.Constants;
import eu.eidas.auth.commons.xml.DocumentBuilderFactoryUtil;
import eu.eidas.auth.commons.xml.opensaml.OpenSamlHelper;
import eu.eidas.encryption.exception.UnmarshallException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

public class SPUtil {
    
    SPUtil() {};

    private static final Logger LOG = LoggerFactory.getLogger(SPUtil.class);
    
    private static final String NO_ASSERTION = "no assertion found";
    
    private static final String ASSERTION_XPATH = "//*[local-name()='Assertion']";
    
    static final int BUFFER_SIZE = 1024;
    
    public static String getConfigFilePath() {
        /*String envLocation = System.getenv().get(Constants.SP_CONFIG_REPOSITORY);
        String configLocation = System.getProperty(Constants.SP_CONFIG_REPOSITORY, envLocation);
        return configLocation;*/
        return ((String)ApplicationContextProvider.getApplicationContext().getBean(Constants.SP_REPO_BEAN_NAME)).trim();
    }
        
    private static Properties loadConfigs(String fileName) throws IOException {
        Properties properties = new Properties();
        FileReader fileReader = null;
        
        try {
        	File f = new File(SPUtil.getConfigFilePath() + fileName);
        	fileReader = new FileReader(f);
        	properties.load(fileReader);
        	
        } finally {
			IOUtils.closeQuietly(fileReader);
		}
        
        return properties;
    }
    
    public static Properties loadSPConfigs() {
        try {
            return SPUtil.loadConfigs(Constants.SP_PROPERTIES);
            
        } catch (IOException e) {
            LOG.error(e.getMessage());
            LOG.error("", e);
            throw new ApplicationSpecificServiceException("Could not load configuration file 'sp.properties': ", e.getMessage());
        }
    }
    
    public static Properties loadCertProxy2Properties() {
        try {
            return SPUtil.loadConfigs(Constants.CERTPROXY2_PROPERTIES);
            
        } catch (IOException e) {
            LOG.error(e.getMessage());
            LOG.error("", e);
            throw new ApplicationSpecificServiceException("Could not load configuration file 'certproxy2.properties': ", e.getMessage());
        }
    }
    
    public static String getCertificatesPath() {
    	Properties certProxy2Properties = SPUtil.loadCertProxy2Properties();
    	String certificatesPath = certProxy2Properties.getProperty("certificates.path");
    	
    	// Se anade al final del path una barra, solo en el caso en que esta no exista
    	certificatesPath = certificatesPath.substring(certificatesPath.length()-1, certificatesPath.length()).equals("/") ? certificatesPath : certificatesPath.concat("/");
    	
    	return certificatesPath;
    }
    
    public static Properties loadCertificatesProperties() {
        try {
        	Properties properties = new Properties();
        	FileReader fileReader = null;
        	
            try {
            	File f = new File(SPUtil.getCertificatesPath() + Constants.CERTIFICATES_PROPERTIES);
            	fileReader = new FileReader(f);
            	properties.load(fileReader);
            	
            } catch(FileNotFoundException fnfe) {
            	LOG.info("El fichero 'certificates.properties' no existe en la ruta '" + SPUtil.getCertificatesPath() + "'. Se creará un fichero nuevo.");
            	
            } finally {
    			IOUtils.closeQuietly(fileReader);
    		}
            
            return properties;
        	
        } catch (IOException e) {
            LOG.error(e.getMessage());
            LOG.error("", e);
            throw new ApplicationSpecificServiceException("Could not load configuration file 'certificates.properties': ", e.getMessage());
        }
    }
    
    /**
     * Returns true when the input contains an encrypted SAML Response
     *
     * @param tokenSaml
     * @return
     * @throws EIDASSAMLEngineException
     */
    public static boolean isEncryptedSamlResponse(byte[] tokenSaml) throws UnmarshallException {
        XMLObject samlObject = OpenSamlHelper.unmarshall(tokenSaml);
        
        if (samlObject instanceof Response) {
            Response response = (Response) samlObject;
            return response.getEncryptedAssertions() != null && !response.getEncryptedAssertions().isEmpty();
        }
        
        return false;
    }

    /**
     * @param samlMsg the saml response as a string
     * @return a string representing the Assertion
     */
    public static String extractAssertionAsString(String samlMsg) {
        String assertion = NO_ASSERTION;
        
        try {
            Document doc = DocumentBuilderFactoryUtil.parse(samlMsg);

            XPath xPath = XPathFactory.newInstance().newXPath();
            Node node = (Node) xPath.evaluate(ASSERTION_XPATH, doc, XPathConstants.NODE);
            if (node != null) {
                assertion = DocumentBuilderFactoryUtil.toString(node);
            }
        
        } catch (ParserConfigurationException pce) {
            LOG.error("cannot parse response {}", pce);
        
        } catch (SAXException saxe) {
            LOG.error("cannot parse response {}", saxe);
        
        } catch (IOException ioe) {
            LOG.error("cannot parse response {}", ioe);
        
        } catch (XPathExpressionException xpathe) {
            LOG.error("cannot find the assertion {}", xpathe);
        
        } catch (TransformerException trfe) {
            LOG.error("cannot output the assertion {}", trfe);
        }
        
        return assertion;
    }
    
    public static byte[] decodeBytesFromBase64(String base64String) {
        return Base64.decode(base64String);
    }
    
    public static String decodeStringFromBase64(String base64String) {
        return bytesToString(decodeBytesFromBase64(base64String));
    }
    
    public static String encodeToBase64(byte[] bytes) {
        if (bytes.length == 0) {
            return StringUtils.EMPTY;
        }
        return bytesToString(Base64.encode(bytes));
    }
    
    public static String encodeToBase64(String value) {
        return encodeToBase64(stringToBytes(value));
    }
    
    public static byte[] stringToBytes(String value) {
        return value.getBytes();
    }
    
    public static String bytesToString(byte[] bytes) {
        return new String(bytes);
    }
    
    public static void writeFile(byte[] data, String filename) {
		if (data != null && UtilsValidation.isValid(filename)) {
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(new File(filename));
				ByteArrayInputStream bais = new ByteArrayInputStream(data);
				byte[] buffer = new byte[BUFFER_SIZE];
				int bytesReaded = 0;
				while ((bytesReaded = bais.read(buffer)) >= 0) {
					fos.write(buffer, 0, bytesReaded);
				}
			} catch (IOException e) {
				LOG.error("", e);
			} finally {
				safeCloseOutputStream(fos);
			}
		} else {
			LOG.error("Error");
		}
	}
    
    public static boolean isSecureConnection(String urlService) {
		return urlService.toLowerCase().startsWith(Constants.HTTPS_PROTOCOL);
	}
    
    public static void safeCloseOutputStream(OutputStream os) {
		if (os != null) {
			try {
				os.close();
			} catch (IOException e) {
				LOG.error("Error en SPUtil.safeCloseOutputStream() - " + os.getClass().getName(), e);
			}
		}
	}
    
}
