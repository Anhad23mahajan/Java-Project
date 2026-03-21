package vaultmind.main;

import vaultmind.service.DatabaseManager;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        int choice = 0;

        while (choice != 3) {
            System.out.println("\n===== VAULTMIND =====");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Enter choice: ");
            choice = scanner.nextInt();
            scanner.nextLine();

            if (choice == 1) {
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                System.out.print("Enter password: ");
                String password = scanner.nextLine();
                DatabaseManager.addUser(username, DatabaseManager.hashPassword(password), "user");

            } else if (choice == 2) {
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                System.out.print("Enter password: ");
                String password = scanner.nextLine();

                String[] user = DatabaseManager.getUser(username);
                if (user != null && user[2].equals(DatabaseManager.hashPassword(password))) {
                    System.out.println("Login successful! Welcome, " + user[1] + " [" + user[3] + "]");
                    int userId = Integer.parseInt(user[0]);

                    if (user[3].equals("admin")) {
                        System.out.println("\nAdmin Panel:");
                        System.out.println("1. View all users");
                        System.out.println("2. Logout");
                        System.out.print("Enter choice: ");
                        int adminChoice = scanner.nextInt();
                        scanner.nextLine();
                        if (adminChoice == 1) {
                            DatabaseManager.getAllUsers();
                        }
                    } else {
                        System.out.println("\nUser Panel:");
                        System.out.println("1. View my files");
                        System.out.println("2. Logout");
                        System.out.print("Enter choice: ");
                        int userChoice = scanner.nextInt();
                        scanner.nextLine();
                        if (userChoice == 1) {
                            DatabaseManager.getFilesByUser(userId);
                        }
                    }
                } else {
                    System.out.println("Invalid username or password.");
                }

            } else if (choice == 3) {
                System.out.println("Goodbye!");
            }
        }
        scanner.close();
    }
}