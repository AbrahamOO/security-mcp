// Loan-approval scoring model used to make an automated decision about applicants.
// No representativeness evaluation anywhere in the repo.
export function scoreApplicant(features: number[]): boolean {
  const model = { predict: (_: number[]) => Math.random() > 0.5 };
  const creditApproved = model.predict(features);
  return creditApproved; // loan approval decision for a candidate applicant
}
