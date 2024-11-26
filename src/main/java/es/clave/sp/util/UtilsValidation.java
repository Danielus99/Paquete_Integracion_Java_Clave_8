package es.clave.sp.util;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

public final class UtilsValidation {
	
	private UtilsValidation() { }
	
	/**
	 * Method that checks if a collection is valid (not null and/or not empty)
	 * (true) or not (false).
	 * 
	 * @param values
	 *            Parameter that represents the collection of values to validate.
	 * @return a boolean that indicates if the collection is valid (not null and/or
	 *         not empty) (true) or not (false).
	 */
	public static boolean isValid(Object... values) {
		boolean isValid = true;
		for (int i = 0; i < values.length && isValid; i++) {
			Object object = values[i];
			if (object == null) {
				return false;
			} else {
				if (object instanceof String) {
					isValid = !StringUtils.isEmpty(object.toString());
				} else if (object instanceof Map<?, ?>) {
					isValid = isValid((Map<?, ?>) object);
				} else if (object instanceof Collection<?>) {
					isValid = isValid((Collection<?>) object);
				} else if (object.getClass().isArray()) {
					isValid = Array.getLength(object) > 0;
				}
			}
		}
		return isValid;
	}

	/**
	 * Method that checks if a map is valid (not null and not empty) (true) or not
	 * (false).
	 * 
	 * @param data
	 *            Parameter that represents the map to validate.
	 * @return a boolean that indicates if the map is valid (not null and not empty)
	 *         (true) or not (false).
	 */
	public static boolean isValid(Map<?, ?> data) {
		if (data == null || data.isEmpty()) {
			return false;
		}
		return true;
	}

	/**
	 * Method that checks if a collection is valid (not null and not empty) (true)
	 * or not (false).
	 * 
	 * @param data
	 *            Parameter that represents the collection to validate.
	 * @return a boolean that indicates if a collection is valid (not null and not
	 *         empty) (true) or not (false).
	 */
	public static boolean isValid(Collection<?> data) {
		if (data == null || data.isEmpty()) {
			return false;
		}
		return true;
	}

}
