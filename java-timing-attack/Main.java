public class Main {
	public static String target = "ThisNCISOperationIsAClassifiedOperationButIDontThinkThisWillReallyWork";
	public static int iterations = 100;
	public static int big_loop = 10000;

	public static void main(String[] args) {
		timeComparisons("something");
		long incorrectLength = timeComparisons("something");
		System.err.println("Time for incorrect-length comparison: " + incorrectLength);

		StringBuilder incorrectSB = new StringBuilder(target);
		incorrectSB.setCharAt(target.length() - 1, ' ');
		String incorrect = incorrectSB.toString();
		timeComparisons(incorrect);
		long incorrectValue = timeComparisons(incorrect);
		System.err.println("Time for incorrect-value comparison:  " + incorrectValue);
		
		String correct = (new StringBuilder(target)).toString();
		timeComparisons(target);
		long correctValue = timeComparisons(target);
		System.err.println("Time for correct-value comparison:  " + correctValue);

		StringBuilder progress = new StringBuilder();
		for (int i = 0; i < target.length(); i++) {
			progress.append(' ');
		}

		String charset = "abcdefghijklmnopqrstuvwxyzABCDEFHIJKLMNOPQRSTUVWXYZ1234567890-_=:!@#$%^&";
		
		for (int pos = 0; pos < target.length(); pos++) {
			long times[] = new long[charset.length()];
			int best_char = -1;
			long best_time = 0;

			for (int i = 0; i < big_loop; i++) {
				for (int char_index = 0; char_index < charset.length(); char_index++) {
					progress.setCharAt(pos, charset.charAt(char_index));
					String attempt = progress.toString();
					long time = timeComparisons(attempt);
					times[char_index] += time;
				}
			}

			for (int char_index = 0; char_index < charset.length(); char_index++) {
				long time = times[char_index];
				if (best_char == -1 || time > best_time) {
					best_time = time;
					best_char = char_index;
				}
			}
			
			System.out.println("Found char at " + pos + ": " + charset.charAt(best_char));
			progress.setCharAt(pos, charset.charAt(best_char));
		}
	}

	public static long timeComparisons(String attempt) {
		long startTime = System.nanoTime();
		int correct = 0;

		for (int i = 0; i < iterations; i++) {
			if (attempt.equals(target)) {
				correct += 0;
			}
		}

		long endTime = System.nanoTime();

		return endTime - startTime;
	}
}
