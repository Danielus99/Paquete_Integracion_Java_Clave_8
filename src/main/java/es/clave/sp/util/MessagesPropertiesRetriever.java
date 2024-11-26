package es.clave.sp.util;

import java.util.ArrayList;
import java.util.Map;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.inject.Named;

import org.springframework.stereotype.Component;

@Named
@Component
public class MessagesPropertiesRetriever {
	
	private PropertyResourceBundle messagesProperties = (PropertyResourceBundle) ResourceBundle.getBundle("messages");
	
	public Map<String, String> getMessagesProperties() {
		return messagesProperties.keySet().stream().collect(Collectors.toMap(Function.identity(), (item) -> messagesProperties.getString(item)));
	}
	
	public String getMessageWithMultipleProps (String keyMessage, ArrayList<String> valuesMultipleProps) {
		String message = getMessagesProperties().get(keyMessage);
		if (message!=null) {
			for (int i=0; i<valuesMultipleProps.size(); i++) {
				message = message.replace("{" + i + "}", valuesMultipleProps.get(i));
			}
			return message;
		}
		return "";
	}
}
