package es.clave.sp.actions;

import java.io.IOException;
import java.util.Properties;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import es.clave.sp.AbstractSPServlet;
import es.clave.sp.ApplicationSpecificServiceException;
import es.clave.sp.Constants;
import es.clave.sp.SessionHolder;
import es.clave.sp.SpProtocolEngineFactory;
import es.clave.sp.util.SPUtil;
import eu.eidas.auth.commons.EidasParameterKeys;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.attribute.PersonType;
import eu.eidas.auth.commons.attribute.impl.StringAttributeValueMarshaller;
import eu.eidas.auth.commons.protocol.IRequestMessageNoMetadata;
import eu.eidas.auth.commons.protocol.eidas.LevelOfAssurance;
import eu.eidas.auth.commons.protocol.eidas.LevelOfAssuranceComparison;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequestNoMetadata;
import eu.eidas.auth.commons.protocol.impl.EidasSamlBinding;
import eu.eidas.auth.commons.protocol.impl.SamlNameIdFormat;
import eu.eidas.auth.engine.ProtocolEngineNoMetadataI;
import eu.eidas.auth.engine.xml.opensaml.SAMLEngineUtils;
import eu.eidas.auth.engine.xml.opensaml.SecureRandomXmlIdGenerator;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 *  This Action Generates a SAML Request with the data given by the user, then sends it to the selected node
 */
public class IndexAction extends AbstractSPServlet {

    private static final long serialVersionUID = 3660074009157921579L;

    private static final Logger LOGGER = LoggerFactory.getLogger(IndexAction.class);

    private final ProtocolEngineNoMetadataI protocolEngine = SpProtocolEngineFactory.getSpProtocolEngine(Constants.SP_CONF);

    private String samlRequest;

    private static Properties configs = SPUtil.loadSPConfigs();
    private static String nodeServiceUrl;
    
    private boolean forceAuthCheck = true;
    private String nameIDPolicy = null;
    
    private boolean afirmaCheck = false;
    private boolean gissCheck = false;
    private boolean aeatCheck = false;
    private boolean eidasCheck = false;
    private boolean mobileCheck = false;

    private static String providerName = "";
    private static String spApplication = ""; 

    private static String returnUrl = null;
    private String eidasloa = null;
    
	@Override
	protected Logger getLogger() {
		return LOGGER;
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		if (acceptsHttpRedirect()) {
			doPost(request, response);
		} else {
			LOGGER.warn("BUSINESS EXCEPTION : redirect binding is not allowed");
		}
	}

	/**
	 * Post method
	 *
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// The input data is parsed
		forceAuthCheck = Boolean.parseBoolean(request.getParameter("forceCheck"));
		gissCheck = Boolean.parseBoolean(request.getParameter("gissCheck"));
		aeatCheck = Boolean.parseBoolean(request.getParameter("aeatCheck"));
		eidasCheck = Boolean.parseBoolean(request.getParameter("eidasCheck"));
		mobileCheck = Boolean.parseBoolean(request.getParameter("mobileCheck"));
		afirmaCheck = Boolean.parseBoolean(request.getParameter("afirmaCheck"));
		nodeServiceUrl = request.getParameter("nodeServiceUrl");
		providerName = request.getParameter("providerName");
		spApplication = request.getParameter("spApplication");
		returnUrl = request.getParameter("returnUrl");
		eidasloa = request.getParameter("eidasloa");
		nameIDPolicy = request.getParameter("nameIDPolicy");

        ImmutableAttributeMap.Builder reqAttrMapBuilder = new ImmutableAttributeMap.Builder();
        if (afirmaCheck) {
        	reqAttrMapBuilder.put(new AttributeDefinition.Builder<String>().nameUri("http://es.minhafp.clave/AFirmaIdP")
        			.friendlyName("AFirmaIdP")
        			.personType(PersonType.NATURAL_PERSON)
        			.required(false)
        			.uniqueIdentifier(true)
        			.xmlType("http://www.w3.org/2001/XMLSchema", "AFirmaIdPType", "cl")
        			.attributeValueMarshaller(new StringAttributeValueMarshaller())
        			.build());
        }
        if (gissCheck) {
        	reqAttrMapBuilder.put(new AttributeDefinition.Builder<String>().nameUri("http://es.minhafp.clave/GISSIdP")
        			.friendlyName("GISSIdP")
        			.personType(PersonType.NATURAL_PERSON)
        			.required(false)
        			.uniqueIdentifier(true)
        			.xmlType("http://www.w3.org/2001/XMLSchema", "GISSIdPType", "cl")
        			.attributeValueMarshaller(new StringAttributeValueMarshaller())
        			.build());
        }
        if (aeatCheck) {
        	reqAttrMapBuilder.put(new AttributeDefinition.Builder<String>().nameUri("http://es.minhafp.clave/AEATIdP")
        			.friendlyName("AEATIdP")
        			.personType(PersonType.NATURAL_PERSON)
        			.required(false)
        			.uniqueIdentifier(true)
        			.xmlType("http://www.w3.org/2001/XMLSchema", "AEATIdPType", "cl")
        			.attributeValueMarshaller(new StringAttributeValueMarshaller())
        			.build());
        }
        if (eidasCheck) {
        	reqAttrMapBuilder.put(new AttributeDefinition.Builder<String>().nameUri("http://es.minhafp.clave/EIDASIdP")
        			.friendlyName("EIDASIdP")
        			.personType(PersonType.NATURAL_PERSON)
        			.required(false)
        			.uniqueIdentifier(true)
        			.xmlType("http://www.w3.org/2001/XMLSchema", "EIDASIdP", "cl")
        			.attributeValueMarshaller(new StringAttributeValueMarshaller())
        			.build());
        }
        if (mobileCheck) {
        	reqAttrMapBuilder.put(new AttributeDefinition.Builder<String>().nameUri("http://es.minhafp.clave/CLVMOVILIdP")
        			.friendlyName("CLVMOVILIdP")
        			.personType(PersonType.NATURAL_PERSON)
        			.required(false)
        			.uniqueIdentifier(true)
        			.xmlType("http://www.w3.org/2001/XMLSchema", "CLVMOVILIdP", "cl")
        			.attributeValueMarshaller(new StringAttributeValueMarshaller())
        			.build());
        }
        
        reqAttrMapBuilder.putPrimaryValues(new AttributeDefinition.Builder<String>().nameUri("http://es.minhafp.clave/RelayState")
    			.friendlyName("RelayState")
    			.personType(PersonType.NATURAL_PERSON)
    			.required(false)
    			.uniqueIdentifier(true)
    			.xmlType("http://eidas.europa.eu/attributes/naturalperson", "PersonIdentifierType", "eidas-natural")
    			.attributeValueMarshaller(new StringAttributeValueMarshaller())
    			.build(), SecureRandomXmlIdGenerator.INSTANCE.generateIdentifier(8));
        
        // build the request
        EidasAuthenticationRequestNoMetadata.Builder reqBuilder = new EidasAuthenticationRequestNoMetadata.Builder();
        reqBuilder.destination(nodeServiceUrl);
        reqBuilder.providerName(providerName);
        reqBuilder.requestedAttributes(reqAttrMapBuilder.build());
        if (LevelOfAssurance.getLevel(eidasloa) == null) {
            reqBuilder.levelOfAssurance(LevelOfAssurance.LOW.stringValue());
        } else {
            reqBuilder.levelOfAssurance(eidasloa);
        }
        
        reqBuilder.levelOfAssuranceComparison(LevelOfAssuranceComparison.fromString("minimum").stringValue());
        
        //urn:oasis:names:tc:SAML:2.0:nameid-format:persistent SamlNameIdFormat.PERSISTENT
		//urn:oasis:names:tc:SAML:2.0:nameid-format:transient SamlNameIdFormat.TRANSIENT
		//urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified SamlNameIdFormat.UNSPECIFIED
        if (nameIDPolicy != null) {
        	reqBuilder.nameIdFormat(nameIDPolicy);
        } else {
        	reqBuilder.nameIdFormat(SamlNameIdFormat.UNSPECIFIED.getNameIdFormat());
        }

        reqBuilder.binding(EidasSamlBinding.EMPTY.getName());
        reqBuilder.assertionConsumerServiceURL(returnUrl);
        reqBuilder.forceAuth(forceAuthCheck);
        
        reqBuilder.spApplication(spApplication);
        
        IRequestMessageNoMetadata binaryRequestMessage = null;
        EidasAuthenticationRequestNoMetadata authRequest = null;
        try {
            reqBuilder.id(SAMLEngineUtils.generateNCName());
            authRequest = reqBuilder.build();
            binaryRequestMessage = protocolEngine.generateRequestMessage(authRequest, true);
        } catch (EIDASSAMLEngineException e) {
            LOGGER.error(e.getMessage());
            LOGGER.error("", e);
            throw new ApplicationSpecificServiceException("Could not generate token for Saml Request",
            		e.getMessage());
        }

        samlRequest = EidasStringUtil.encodeToBase64(binaryRequestMessage.getMessageBytes());
        
        request.setAttribute("samlRequest", samlRequest);
		request.setAttribute("RelayState", SecureRandomXmlIdGenerator.INSTANCE.generateIdentifier(8));
		request.setAttribute("nodeServiceUrl", nodeServiceUrl);
		request.setAttribute(EidasParameterKeys.BINDING.toString(), getRedirectMethod());
		
		SessionHolder.sessionsSAML.put(authRequest.getId(), (String) request.getAttribute("RelayState"));
		
		RequestDispatcher dispatcher = request.getRequestDispatcher("/redirect.jsp");
		dispatcher.forward(request, response);
    }
    
    /**
     * Method to be used by configuration. See sp.properties -> redirect.method key.
     *  This allows to be able to function eihter in
     * EIDAS or STORK mode respectively.
     *
     * @return a redirect method
     */
    public String getRedirectMethod() {
    	String ret = "post";
    	if (configs.containsKey(Constants.REDIRECT_METHOD)) {
    		ret = configs.getProperty(Constants.REDIRECT_METHOD);
			if (ret == null || ret.trim().isEmpty() || !(ret.equals("post") || ret.equals("get"))) {
				LOGGER.error("La variable de configuracion redirect.method no contiene un valor adecuado: " + ret);
				ret = "post";
			}
    	}
    	return ret;
    }
}
