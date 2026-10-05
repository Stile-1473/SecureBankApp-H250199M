package securebank.exception;

import java.util.List;


/*
This is thrown when a user input fails validation.Carries every problem found so the user can fix them all at once instead of one at time
 */
public class ValidationException extends BankException{

    private static final long serialVersionUID = 1L;

   private final transient List<String> problems;

   public ValidationException(String problem){
       this(List.of(problem));
   }

   public ValidationException(List<String> problems){
       super(String.join("; ",problems));
       this.problems = List.copyOf(problems);
   }

   public List<String> getProblems() {
       return  problems;
   }

}
