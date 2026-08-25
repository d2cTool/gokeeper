package vault

import "fmt"

// Type — вид секрета из ТЗ.
type Type string

// Допустимые типы записей хранилища.
const (
	TypeLogin  Type = "login"
	TypeText   Type = "text"
	TypeBinary Type = "binary"
	TypeCard   Type = "card"
)

// ParseType проверяет значение типа.
func ParseType(s string) (Type, error) {
	t := Type(s)
	switch t {
	case TypeLogin, TypeText, TypeBinary, TypeCard:
		return t, nil
	default:
		return "", fmt.Errorf("unknown item type %q", s)
	}
}

// LoginPayload — пара логин/пароль и адрес ресурса.
type LoginPayload struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// TextPayload — произвольный текст.
type TextPayload struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// BinaryPayload — файл в пределах лимита сервера.
type BinaryPayload struct {
	Filename string `json:"filename"`
	Data     []byte `json:"data"`
}

// CardPayload — данные банковской карты.
type CardPayload struct {
	Holder   string `json:"holder"`
	Number   string `json:"number"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	CVV      string `json:"cvv"`
}

// Item — расшифрованная запись сейфа.
type Item struct {
	ID        string         `json:"id"`
	Type      Type           `json:"type"`
	Metadata  string         `json:"metadata"`
	Version   int64          `json:"version"`
	UpdatedAt int64          `json:"updated_at"`
	Deleted   bool           `json:"deleted,omitempty"`
	Origin    string         `json:"origin,omitempty"`
	Login     *LoginPayload  `json:"login,omitempty"`
	Text      *TextPayload   `json:"text,omitempty"`
	Binary    *BinaryPayload `json:"binary,omitempty"`
	Card      *CardPayload   `json:"card,omitempty"`
}

// Title возвращает человекочитаемый заголовок для списка.
func (it Item) Title() string {
	switch it.Type {
	case TypeLogin:
		if it.Login != nil {
			if it.Login.URL != "" {
				return it.Login.URL
			}
			return it.Login.Username
		}
	case TypeText:
		if it.Text != nil && it.Text.Title != "" {
			return it.Text.Title
		}
	case TypeBinary:
		if it.Binary != nil {
			return it.Binary.Filename
		}
	case TypeCard:
		if it.Card != nil {
			n := it.Card.Number
			if len(n) >= 4 {
				return "•••• " + n[len(n)-4:]
			}
			return it.Card.Holder
		}
	}
	if it.Metadata != "" {
		return it.Metadata
	}
	return string(it.Type)
}

type storedPayload struct {
	Metadata string         `json:"metadata"`
	Login    *LoginPayload  `json:"login,omitempty"`
	Text     *TextPayload   `json:"text,omitempty"`
	Binary   *BinaryPayload `json:"binary,omitempty"`
	Card     *CardPayload   `json:"card,omitempty"`
}
