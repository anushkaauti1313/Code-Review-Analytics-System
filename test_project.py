
# Student Library Management System
# Author: Test Project
# WARNING: This file contains intentional defects for demonstration purposes

import os
import sys
import json
import math
import datetime
import random
import re
from math import *    # wildcard import - Minor defect


# ─── CONSTANTS (bad naming style) ───────────────────────────────────────────
MaxBooks = 500          # should be MAX_BOOKS - Minor
defaultFine = 2.5       # should be DEFAULT_FINE - Minor
libraryName = "City Library"   # should be LIBRARY_NAME - Minor


# ─── CLASS: Book ─────────────────────────────────────────────────────────────
class book:             # class name should be PascalCase - Minor
    # Missing class docstring - Minor

    def __init__(self, id, title, author, genre, year):
        self.id = id
        self.Title = title        # inconsistent attribute naming
        self.author = author
        self.Genre = genre        # inconsistent attribute naming
        self.year = year
        self.is_available = True
        self.borrow_count = 0

    def display(self):
        # Missing function docstring - Minor
        print("ID:", self.id)
        print("Title:", self.Title)
        print("Author:", self.author)
        print("Genre:", self.Genre)
        print("Year:", self.year)
        print("Available:", self.is_available)

    def borrow(self):
        if self.is_available == True:    # redundant comparison - Minor
            self.is_available = False
            self.borrow_count = self.borrow_count + 1
            return True
        else:
            return False

    def returnBook(self):       # method should use snake_case - Minor
        self.is_available = True

    def getDetails(self):       # method should use snake_case - Minor
        details = {
            "id": self.id,
            "title": self.Title,
            "author": self.author,
            "genre": self.Genre,
            "year": self.year,
            "available": self.is_available,
            "borrow_count": self.borrow_count
        }
        return details


# ─── CLASS: Member ───────────────────────────────────────────────────────────
class Member:

    def __init__(self,name,email,phone,membership_type):   # missing spaces after commas
        self.name=name          # missing spaces around =
        self.email=email
        self.phone=phone
        self.membership_type=membership_type
        self.borrowed_books=[]
        self.fine_amount=0
        self.join_date=datetime.datetime.now()
        self.member_id = random.randint(1000,9999)

    def borrow_book(self,book_obj):
        if len(self.borrowed_books)>=5:
            print("Borrow limit reached")
            return False
        if book_obj.borrow()==True:     # redundant comparison
            self.borrowed_books.append(book_obj.id)
            return True
        return False

    def return_book(self,book_id,book_obj):
        if book_id in self.borrowed_books:
            self.borrowed_books.remove(book_id)
            book_obj.returnBook()
            return True
        else:
            return False

    def calculate_fine(self,due_date):
        today = datetime.datetime.now()
        delta = today - due_date
        days_late = delta.days
        if days_late>0:
            self.fine_amount = self.fine_amount + (days_late*defaultFine)
        return self.fine_amount

    def pay_fine(self,amount):
        if amount>=self.fine_amount:
            self.fine_amount=0
            print("Fine paid successfully")
        else:
            self.fine_amount=self.fine_amount-amount
            print("Partial payment. Remaining:", self.fine_amount)

    def getMemberInfo(self):        # should be get_member_info - Minor
        return {
            "id": self.member_id,
            "name": self.name,
            "email": self.email,
            "borrowed": self.borrowed_books,
            "fine": self.fine_amount
        }


# ─── CLASS: Library (many issues) ─────────────────────────────────────────────
class Library:

    def __init__(self):
        self.books = {}
        self.members = {}
        self.transactions = []
        self.revenue = 0
        self.totalBooksAdded = 0    # should be total_books_added - Minor

    def addBook(self,id,title,author,genre,year):   # should be add_book - Minor
        # Missing docstring
        b = book(id,title,author,genre,year)
        self.books[id] = b
        self.totalBooksAdded+=1
        print("Book added:", title)

    def removeBook(self,book_id):   # should be remove_book - Minor
        if book_id in self.books:
            del self.books[book_id]
            print("Book removed")
        else:
            print("Book not found")

    def registerMember(self,name,email,phone,mtype="standard"):   # should be register_member
        m = Member(name,email,phone,mtype)
        self.members[m.member_id] = m
        print(f"Member registered: {name} (ID: {m.member_id})")
        return m.member_id

    def searchBook(self,query):     # should be search_book
        # this function is too long and does too many things
        results = []
        query_lower = query.lower()

        for book_id, b in self.books.items():
            found = False
            if query_lower in b.Title.lower():
                found = True
            if query_lower in b.author.lower():
                found = True
            if query_lower in b.Genre.lower():
                found = True
            if query_lower in str(b.year):
                found = True
            if found == True:       # redundant comparison - Minor
                results.append(b.getDetails())

        if len(results) == 0:       # could use `not results` - Minor
            print("No books found for query:", query)
            return []

        print(f"Found {len(results)} book(s) matching '{query}'")
        return results

    def borrowBook(self,member_id,book_id):     # should be borrow_book
        if member_id not in self.members:
            print("Member not found")
            return False
        if book_id not in self.books:
            print("Book not found")
            return False

        member = self.members[member_id]
        book_obj = self.books[book_id]

        result = member.borrow_book(book_obj)
        if result == True:      # redundant comparison - Minor
            due_date = datetime.datetime.now() + datetime.timedelta(days=14)
            self.transactions.append({
                "type": "borrow",
                "member_id": member_id,
                "book_id": book_id,
                "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                "due_date": due_date.strftime("%Y-%m-%d")
            })
            print(f"Book '{book_obj.Title}' borrowed by {member.name}")
            print(f"Due date: {due_date.strftime('%Y-%m-%d')}")
            return True
        else:
            print("Could not borrow book")
            return False

    def returnBook(self,member_id,book_id):     # should be return_book
        if member_id not in self.members:
            print("Member not found")
            return False
        if book_id not in self.books:
            print("Book not found")
            return False

        member = self.members[member_id]
        book_obj = self.books[book_id]
        result = member.return_book(book_id, book_obj)

        if result:
            self.transactions.append({
                "type": "return",
                "member_id": member_id,
                "book_id": book_id,
                "date": datetime.datetime.now().strftime("%Y-%m-%d")
            })
            print(f"Book '{book_obj.Title}' returned by {member.name}")
            return True
        return False

    def generateReport(self):       # should be generate_report
        totalBooks = len(self.books)        # should be total_books
        availableBooks = 0                  # should be available_books
        borrowedBooks = 0                   # should be borrowed_books
        totalMembers = len(self.members)    # should be total_members

        for b in self.books.values():
            if b.is_available == True:      # redundant
                availableBooks+=1
            else:
                borrowedBooks+=1

        popularBooks = []
        for b in self.books.values():
            if b.borrow_count > 0:
                popularBooks.append((b.Title, b.borrow_count))

        popularBooks.sort(key=lambda x: x[1], reverse=True)

        print("\n===== LIBRARY REPORT =====")
        print(f"Library: {libraryName}")
        print(f"Total Books: {totalBooks}")
        print(f"Available: {availableBooks}")
        print(f"Borrowed: {borrowedBooks}")
        print(f"Total Members: {totalMembers}")
        print(f"Total Transactions: {len(self.transactions)}")
        print("\nTop 5 Popular Books:")
        for i in range(len(popularBooks)):      # should use enumerate
            print(f"  {i+1}. {popularBooks[i][0]} - borrowed {popularBooks[i][1]} time(s)")
        print("==========================\n")

    def save_to_file(self,filename):
        data = {
            "books": {str(k): v.getDetails() for k,v in self.books.items()},
            "members": {str(k): v.getMemberInfo() for k,v in self.members.items()},
            "transactions": self.transactions
        }
        try:
            f = open(filename, "w")      # should use context manager - Minor
            json.dump(data, f, indent=2, default=str)
            f.close()
            print(f"Data saved to {filename}")
        except:                          # bare except - Major
            print("Error saving file")

    def load_from_file(self,filename):
        try:
            f = open(filename, "r")      # should use context manager
            data = json.load(f)
            f.close()
            print(f"Data loaded from {filename}")
            return data
        except Exception:                # broad except - Major
            print("Error loading file")
            return None


# ─── UTILITY FUNCTIONS (various issues) ─────────────────────────────────────

def ValidateEmail(email):       # should be validate_email - Minor
    # Missing docstring
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if re.match(pattern, email):
        return True
    else:
        return False            # could simplify to: return bool(re.match(...))


def CalculateFineTotal(members_dict):   # should be calculate_fine_total - Minor
    Total = 0                           # variable should be total
    for id, member in members_dict.items():
        Total = Total + member.fine_amount
    return Total


def PrintStats(library_obj):    # should be print_stats - Minor
    count = 0
    total_borrows = 0
    genres = {}
    unused_data = []            # unused variable - Major

    for book_id, b in library_obj.books.items():
        count+=1
        total_borrows += b.borrow_count
        if b.Genre in genres:
            genres[b.Genre] = genres[b.Genre] + 1
        else:
            genres[b.Genre] = 1

    print(f"\nTotal books catalogued: {count}")
    print(f"Total borrows across all books: {total_borrows}")
    print("\nBooks by Genre:")
    for g in genres:
        print(f"  {g}: {genres[g]}")


def get_overdue_books(library_obj, days_threshold=7):
    overdue = []
    for t in library_obj.transactions:
        if t["type"] == "borrow":
            due = datetime.datetime.strptime(t["due_date"], "%Y-%m-%d")
            today = datetime.datetime.now()
            if (today - due).days > days_threshold:
                overdue.append(t)
    return overdue


def recommend_books(library_obj, genre, limit=5):
    recommendations = []
    for b in library_obj.books.values():
        if b.Genre.lower() == genre.lower() and b.is_available:
            recommendations.append(b.getDetails())
    recommendations.sort(key=lambda x: x["borrow_count"], reverse=True)
    return recommendations[:limit]


def BulkAddBooks(library_obj, books_list):  # should be bulk_add_books - Minor
    added = 0
    failed = 0
    for item in books_list:
        try:
            library_obj.addBook(
                item["id"], item["title"],
                item["author"], item["genre"], item["year"]
            )
            added+=1
        except Exception as e:
            print("Failed to add book:", e)
            failed+=1
    print(f"Bulk add complete: {added} added, {failed} failed")


def ApplyDiscount(price, discount_pct):  # should be apply_discount - Minor
    # Missing docstring
    if discount_pct < 0 or discount_pct > 100:
        print("Invalid discount")
        return price
    discounted = price - (price * discount_pct / 100)
    return discounted


def CheckAvailability(library_obj, book_ids):   # should be check_availability
    results = {}
    for bid in book_ids:
        if bid in library_obj.books:
            results[bid] = library_obj.books[bid].is_available
        else:
            results[bid] = None
    return results


# ─── MAIN EXECUTION ──────────────────────────────────────────────────────────

def main():
    print("Initialising Library Management System...\n")

    lib = Library()

    # Add sample books
    BulkAddBooks(lib, [
        {"id": 101, "title": "Clean Code",            "author": "Robert C. Martin", "genre": "Programming", "year": 2008},
        {"id": 102, "title": "The Pragmatic Programmer","author": "David Thomas",   "genre": "Programming", "year": 1999},
        {"id": 103, "title": "Design Patterns",        "author": "Gang of Four",    "genre": "Programming", "year": 1994},
        {"id": 104, "title": "Python Crash Course",    "author": "Eric Matthes",    "genre": "Programming", "year": 2019},
        {"id": 105, "title": "Dune",                   "author": "Frank Herbert",   "genre": "Science Fiction","year": 1965},
        {"id": 106, "title": "Foundation",             "author": "Isaac Asimov",    "genre": "Science Fiction","year": 1951},
        {"id": 107, "title": "Sapiens",                "author": "Yuval Harari",    "genre": "Non-fiction",  "year": 2011},
        {"id": 108, "title": "Atomic Habits",          "author": "James Clear",     "genre": "Self-Help",    "year": 2018},
    ])

    # Register members
    id1 = lib.registerMember("Alice Johnson", "alice@example.com", "9876543210", "premium")
    id2 = lib.registerMember("Bob Smith",     "bob@example.com",   "9123456780", "standard")
    id3 = lib.registerMember("Carol White",   "carol@example.com", "9988776655", "student")

    # Borrow some books
    lib.borrowBook(id1, 101)
    lib.borrowBook(id1, 105)
    lib.borrowBook(id2, 102)
    lib.borrowBook(id3, 107)

    # Return a book
    lib.returnBook(id1, 101)

    # Search
    print("\n--- Search Results for 'Python' ---")
    results = lib.searchBook("Python")

    # Stats
    PrintStats(lib)

    # Recommendations
    print("\n--- Programming Book Recommendations ---")
    recs = recommend_books(lib, "Programming")
    for r in recs:
        print(f"  - {r['title']} by {r['author']}")

    # Validate emails
    test_emails = ["alice@example.com", "invalid-email", "test@test.org"]
    print("\n--- Email Validation ---")
    for email in test_emails:
        valid = ValidateEmail(email)
        print(f"  {email}: {'Valid' if valid else 'Invalid'}")

    # Fine calculation
    overdue_date = datetime.datetime.now() - datetime.timedelta(days=20)
    member = lib.members[id2]
    fine = member.calculate_fine(overdue_date)
    print(f"\nFine for {member.name}: ₹{fine}")

    # Generate report
    lib.generateReport()

    # Save data
    lib.save_to_file("library_data.json")

    # Check availability
    availability = CheckAvailability(lib, [101, 102, 103, 999])
    print("\nAvailability Check:", availability)

    print("\nSystem demo complete.")


if __name__ == "__main__":
    main()
