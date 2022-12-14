package northwind.exception;

public class CoreException extends Exception {
 
	private static final long serialVersionUID = 74411041929905117L;
	private String message;
    private int statusCode;

    public CoreException(String message, int statusCode) {
        super(message);
        this.message = message;
        this.statusCode = statusCode;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
