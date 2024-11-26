package es.clave.sp.daemon;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import javax.inject.Inject;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.clave.sp.Constants;
import es.clave.sp.util.MessagesPropertiesRetriever;
import es.clave.sp.util.SPUtil;

@Component
public class DaemonCertificateProxy2 {
    
    public DaemonCertificateProxy2() {
        // constructor vacio
    }
    
    @Inject
    private MessagesPropertiesRetriever messagesProperties;
    
    private static Properties certProxy2Properties = SPUtil.loadCertProxy2Properties();
    
    private final Logger log = LoggerFactory.getLogger(DaemonCertificateProxy2.class);
    
    @Scheduled(fixedRateString = "${certProxy2.daemon.fixedRate}")
    public void recoverAndUpdatePublicCertificates() {
        String hostname = null;
        String message;
        String errorMessage;
        
        // Flag que indica si el daemon esta o no activo
        String daemonActivated = certProxy2Properties.getProperty("certProxy2.daemon.activated");
        if (daemonActivated == null || !"true".equals(daemonActivated)) {
        	message = messagesProperties.getMessagesProperties().get("daemonCertificateProxy2.daemonCertificateProxy2Deactivated");
            log.info(message);
        	return;
        }
        
        message = messagesProperties.getMessagesProperties().get("daemonCertificateProxy2.daemonCertificateProxy2StartInfo");
        log.info(message);
        
        try {
            try {
                InetAddress ip = InetAddress.getLocalHost();
                hostname = ip.getHostName();
                
                // Ejecucion del 'DaemonCertificateProxy2' en el nodo {hostname}
                message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.actualNodeInfo",
                        new ArrayList<String>(Arrays.asList(hostname)));
                log.info(message);
                
            } catch (UnknownHostException e) {
                // No se ha podido obtener el 'hostname' del servidor
                errorMessage = messagesProperties.getMessagesProperties().get("daemonCertificateProxy2.unknownHostname");
                log.warn(errorMessage, e);
            }
            
            // Se abre una conexion HTTP o HTTPS de tipo GET que consume el servlet ofrecido por el modulo 'Proxy2' de CLAVE2.
            // La URL de esta conexion se configura en la propiedad 'certproxy2.endpoint' del fichero 'certproxy2.properties'.
            // A traves de esta llamada obtenemos un XML con los diferentes certificados publicos existentes en la BDD de CLAVE. Se obtiene la siguiente informacion:
            //   tipo de certificado: de firma (signing), o de cifrado (encryption)
            //   nombre del certificado: 'proxy_sign_*' o 'proxy_cipher_*'
            //   contenido del certificado en Base64
            //   estado certificado: activo / inactivo
            
            String certproxy2Endpoint = certProxy2Properties.getProperty("certproxy2.endpoint");
            message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.connectingToURL",
                    new ArrayList<String>(Arrays.asList(certproxy2Endpoint)));
            log.info(message);
            
            try {
            	HttpsURLConnection servletConnectionHttps = null;
            	HttpURLConnection servletConnectionHttp = null;
            	
            	// Si la conexion es segura: 'https'
            	if (SPUtil.isSecureConnection(certproxy2Endpoint)) {
            		try {
            			// Se carga el keystore 'TrustStore.jks'
            			FileInputStream truststoreFile = new FileInputStream(SPUtil.getConfigFilePath() + certProxy2Properties.getProperty("truststore.path"));
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
                        char[] trustorePassword = certProxy2Properties.getProperty("truststore.password").toCharArray();
                        truststore.load(truststoreFile, trustorePassword);
                        trustManagerFactory.init(truststore);
                        
                        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                        sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
                        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
                        
                        URL httpsUrl = new URL(certproxy2Endpoint);
                        servletConnectionHttps = (HttpsURLConnection) httpsUrl.openConnection();
                        servletConnectionHttps.setSSLSocketFactory(socketFactory);
                        servletConnectionHttps.setRequestMethod("GET");
                        servletConnectionHttps.setRequestProperty("Content-Type", "application/octet-stream");
                        
                    } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
                        e.printStackTrace();
                    } catch (KeyManagementException e) {
                    	e.printStackTrace();
                    }
            		
            	// Si la conexion no es segura: 'http'
                } else {
                	URL httpUrl = new URL(certproxy2Endpoint);
                    servletConnectionHttp = (HttpURLConnection) httpUrl.openConnection();
                    servletConnectionHttp.setRequestMethod("GET");
                    servletConnectionHttp.setRequestProperty("Content-Type", "application/octet-stream");
                }
            	
                Map<String, String> certificatesStateMap = new HashMap<String, String>();
                Map<String, String> certificatesUpdatedMap = new HashMap<String, String>();
                
                // Se recuperan los pares atributo/valor del fichero 'certificates.properties'
                Properties certificatesProperties = SPUtil.loadCertificatesProperties();
                Enumeration<Object> keys = certificatesProperties.keys();
                while (keys.hasMoreElements()) {
                	String certificateName;
                    String key = (String) keys.nextElement();
                    String val = (String) certificatesProperties.get(key);
                    
                    if (key.endsWith(".state")) {
                    	certificateName = key.replace(".state","");
                        certificatesStateMap.put(certificateName, val);
                    }
                    if (key.endsWith(".updated")) {
                    	certificateName = key.replace(".updated","");
                        certificatesUpdatedMap.put(certificateName, val);
                    }
                }
                
                // Una vez recuperados los pares atributo/valor del fichero 'certificates.properties', se eliminan para dejar el fichero de propiedades en blanco
                certificatesProperties.clear();
                
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                try {
                    // Process XML securely, avoid attacks like XML External Entities (XXE)
                    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                    
                    // Parse XML file
                    DocumentBuilder db = dbf.newDocumentBuilder();
                    Document doc;
                    if (SPUtil.isSecureConnection(certproxy2Endpoint)) {
                    	doc = db.parse(servletConnectionHttps.getInputStream());
                    } else {
                    	doc = db.parse(servletConnectionHttp.getInputStream());
                    }
                    doc.getDocumentElement().normalize();
                    
                    String certificateUse;
                    String certificateKeyName;
                    String certificateX509Certificate;
                    String certificateMgmtData;
                    
                    NodeList IDPSSODescriptorNodeList = doc.getElementsByTagName("md:IDPSSODescriptor");
                    Node IDPSSODescriptorNode = IDPSSODescriptorNodeList.item(0);
                    
                    for (int i=0; i < IDPSSODescriptorNode.getChildNodes().getLength(); i++) {
                        Node KeyDescriptorNode = IDPSSODescriptorNode.getChildNodes().item(i);
                        Element KeyDescriptorNodeElement = (Element) KeyDescriptorNode;
                        
                        if (KeyDescriptorNode.getNodeName() == "md:KeyDescriptor") {
                            // Tipo de certificado: de firma (signing) / de cifrado (encryption)
                            certificateUse = KeyDescriptorNodeElement.getAttribute("use");
                            
                            Node KeyInfoNode = KeyDescriptorNode.getChildNodes().item(0);
                            Element KeyInfoElement = (Element) KeyInfoNode;
                            
                            // Nombre de certificado: de firma (proxy_sign_*) / de cifrado (proxy_cipher_*)
                            
                            certificateKeyName = KeyInfoElement.getElementsByTagName("ds:KeyName").item(0).getTextContent();
                            
                            Node X509DataNode = KeyInfoElement.getElementsByTagName("ds:X509Data").item(0);
                            Element X509DataElement = (Element) X509DataNode;
                            // Valor del certificado en Base64
                            certificateX509Certificate = X509DataElement.getElementsByTagName("ds:X509Certificate").item(0).getTextContent();
                            
                            // Estado del certificado: active / inactive
                            certificateMgmtData = KeyInfoElement.getElementsByTagName("ds:MgmtData").item(0).getTextContent();
                            
                            // INICIO ALGORITMO DE ACTUZALIZACION Y RECUPERACION DE CERTIFICADOS PUBLICOS
                            // Si el nombre del certificado obtenido a traves del XML existe en el fichero de propiedades 'certificates.properties'...
                            if (certificatesStateMap.get(certificateKeyName)!=null) {
                                // Si el estado del certificado obtenido es igual al del fichero de propiedades...
                                if (certificatesStateMap.get(certificateKeyName).equals(certificateMgmtData)) {
                                	if (certificateUse.equals("signing")) {
                                		// Certificado de firma {certificateKeyName} ya existe
                                		message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.signatureCertificateExists",
                                                new ArrayList<String>(Arrays.asList(certificateKeyName)));
                                	} else {
                                		// Certificado de cifrado {certificateKeyName} ya existe
                                		message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.encryptionCertificateExists",
                                                new ArrayList<String>(Arrays.asList(certificateKeyName)));
                                	}
                                    log.info(message);
                                    
                                // Si el estado del certificado obtenido es diferente al del fichero de propiedades...
                                } else {
                                	// Se descarga el certificado en el path de certificados y se actualiza en el fichero de propiedades 'certificates.properties'
                                	downloadCertificate("certificateUpdated", certificateUse, certificateKeyName, certificateX509Certificate, certificateMgmtData,
                                			certificatesStateMap, certificatesUpdatedMap);
                                }
                                
                            // Si el nombre del certificado obtenido a traves del XML no existe en el fichero de propiedades 'certificates.properties'...
                            } else {
                            	// Se descarga el certificado en el path de certificados y se inserta en el fichero de propiedades 'certificates.properties'
                            	downloadCertificate("certificateDownloaded", certificateUse, certificateKeyName, certificateX509Certificate, certificateMgmtData,
                            			certificatesStateMap, certificatesUpdatedMap);
                            }
                        }
                    }
                    
                    // Se rellena el fichero 'certificates.properties' con la nueva informacion de los certificados actualizados
                    Iterator<Map.Entry<String, String>> iterator = certificatesStateMap.entrySet().iterator();
                    while (iterator.hasNext()) {
                    	String certificateName;
                    	Map.Entry<String, String> pairs = iterator.next();
                    	certificateName = pairs.getKey();
                    	certificatesProperties.setProperty(certificateName.concat(".state"), pairs.getValue());
                    	certificatesProperties.setProperty(certificateName.concat(".updated"), certificatesUpdatedMap.get(certificateName));
                    	iterator.remove(); // avoids a ConcurrentModificationException
                    }
                    
                    FileOutputStream out = new FileOutputStream(SPUtil.getCertificatesPath().concat(Constants.CERTIFICATES_PROPERTIES));
                    certificatesProperties.store(out, null);
                    out.close();
                    
                } catch (ParserConfigurationException | SAXException | IOException e) {
                    e.printStackTrace();
                }
                
            } catch (MalformedURLException e) {
                e.printStackTrace();
                
            } catch (IOException e) {
                e.printStackTrace();
            }
            
        } catch (Exception e) {
            log.error("Error in DaemonCertificateProxy2", e);
        }
        
        message = messagesProperties.getMessagesProperties().get("daemonCertificateProxy2.daemonCertificateProxy2EndInfo");
        log.info(message);
    }
    
    private void downloadCertificate(String actionType, String certificateUse, String certificateKeyName, String certificateX509Certificate, String certificateMgmtData,
    		Map<String, String> certificatesStateMap, Map<String, String> certificatesUpdatedMap) {
    	
    	SimpleDateFormat isoDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
    	String nowAsISO = isoDate.format(new Date());
    	
        SPUtil.writeFile(SPUtil.decodeBytesFromBase64(certificateX509Certificate), SPUtil.getCertificatesPath().concat(certificateKeyName).concat(".cer"));
        
        certificatesStateMap.put(certificateKeyName, certificateMgmtData);
        certificatesUpdatedMap.put(certificateKeyName, nowAsISO);
        
        String message;
        // Actualizacion de certificado
        if (actionType.equals("certificateUpdated")) {
        	if (certificateUse.equals("signing")) {
        		// Certificado de firma '{certificateKeyName}' actualizado
            	message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.signatureCertificateUpdated",
                        new ArrayList<String>(Arrays.asList(certificateKeyName)));
        	} else {
        		// Certificado de cifrado '{certificateKeyName}' actualizado
            	message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.encryptionCertificateUpdated",
                        new ArrayList<String>(Arrays.asList(certificateKeyName)));
        	}
        
        // Descarga de certificado
        } else {
        	if (certificateUse.equals("signing")) {
        		// Certificado de firma '{certificateKeyName}' descargado
            	message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.signatureCertificateDownloaded",
                        new ArrayList<String>(Arrays.asList(certificateKeyName)));
        	} else {
        		// Certificado de cifrado '{certificateKeyName}' descargado
            	message = messagesProperties.getMessageWithMultipleProps("daemonCertificateProxy2.encryptionCertificateDownloaded",
                        new ArrayList<String>(Arrays.asList(certificateKeyName)));
        	}
        	
        }
        log.info(message);
    }
}
