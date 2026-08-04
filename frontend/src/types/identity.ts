export type UserPersona = "consumer" | "employee";

export type EmployeeProfile = {
  employeeId: string;
  departmentName: string;
  title: string;
};

export type CurrentUser = {
  userId: string;
  displayName: string;
  email: string;
  phoneMasked: string;
  personas: UserPersona[];
  employeeProfile?: EmployeeProfile;
};
