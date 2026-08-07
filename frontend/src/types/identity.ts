//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Identity contract types shared across the frontend
//

export type UserPersona = "consumer" | "employee";

export type EmployeeProfile = {
  employeeId: string;
  departmentName: string;
  title: string;
};

export type CurrentUser = {
  userId: string;
  displayName: string;
  nickname?: string;
  avatarUrl?: string;
  email: string;
  phoneMasked: string;
  personas: UserPersona[];
  employeeProfile?: EmployeeProfile;
};
