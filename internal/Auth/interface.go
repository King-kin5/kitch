package Auth
type Userstore interface{
	CreateUser(user User) error
	GetUserByEmail(email string) (User, error)
	GetUserByID(ID string) (User, error)
	GetUserByName(name string) (User, error)
	UpdateUserInfoByID(ID string, user User) error
	CheckDBConnection() error

}