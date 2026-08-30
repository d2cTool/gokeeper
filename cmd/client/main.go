// Command gophkeeper — кроссплатформенный gRPC CLI для GophKeeper.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"gokeeper/internal/clientcfg"
	"gokeeper/internal/transport/grpc/pb"
	"gokeeper/pkg/version"
)

// tlsCertFlag задаётся persistent-флагом --tls-cert в rootCmd.
var tlsCertFlag *string

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		addr     string
		insecure bool
		tlsCert  string
	)
	cmd := &cobra.Command{
		Use:   "gophkeeper",
		Short: "CLI-клиент GophKeeper (gRPC)",
	}
	cmd.PersistentFlags().StringVar(&addr, "addr", "", "хост:порт gRPC (по умолчанию из конфига)")
	cmd.PersistentFlags().BoolVar(&insecure, "insecure", false, "без TLS")
	cmd.PersistentFlags().StringVar(&tlsCert, "tls-cert", "", "публичный сертификат сервера (tls.crt)")
	tlsCertFlag = &tlsCert
	cmd.AddCommand(
		versionCmd(),
		registerCmd(&addr, &insecure),
		loginCmd(&addr, &insecure),
		logoutCmd(&addr, &insecure),
		listCmd(&addr, &insecure),
		getCmd(&addr, &insecure),
		addCmd(&addr, &insecure),
		editCmd(&addr, &insecure),
		rmCmd(&addr, &insecure),
		syncCmd(&addr, &insecure),
	)
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Версия и дата сборки клиента",
		Run: func(_ *cobra.Command, _ []string) {
			info := version.Current()
			fmt.Printf("gophkeeper %s\nbuild: %s\ngo: %s %s/%s\n",
				info.Version, info.BuildDate, info.GoVersion, info.OS, info.Arch)
		},
	}
}

func registerCmd(addr *string, insc *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "register [login]",
		Short: "Регистрация на сервере",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			login, pass, err := credentialsFromArgs(args)
			if err != nil {
				return err
			}
			return withAuthClient(*addr, *insc, false, func(ctx context.Context, c pb.AuthServiceClient, cfg clientcfg.Config) error {
				resp, err := c.Register(ctx, pb.AuthRequest_builder{Login: login, Password: pass}.Build())
				if err != nil {
					return err
				}
				return saveTokens(cfg, resp, *addr, *insc)
			})
		},
	}
}

func loginCmd(addr *string, insc *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "login [login]",
		Short: "Вход и сохранение JWT",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			login, pass, err := credentialsFromArgs(args)
			if err != nil {
				return err
			}
			return withAuthClient(*addr, *insc, false, func(ctx context.Context, c pb.AuthServiceClient, cfg clientcfg.Config) error {
				resp, err := c.Login(ctx, pb.AuthRequest_builder{Login: login, Password: pass}.Build())
				if err != nil {
					return err
				}
				return saveTokens(cfg, resp, *addr, *insc)
			})
		},
	}
}

func logoutCmd(addr *string, insc *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Завершить сессию",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withAuthClient(*addr, *insc, true, func(ctx context.Context, c pb.AuthServiceClient, cfg clientcfg.Config) error {
				_, err := c.Logout(ctx, pb.LogoutRequest_builder{}.Build())
				cfg.Token = ""
				_ = cfg.Save()
				return err
			})
		},
	}
}

func listCmd(addr *string, insc *bool) *cobra.Command {
	var typ string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Список записей",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
				resp, err := c.List(ctx, pb.ListRequest_builder{Type: typ}.Build())
				if err != nil {
					return err
				}
				return printJSON(resp.GetItems())
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "login|text|card|binary")
	return cmd
}

func getCmd(addr *string, insc *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Показать запись",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
				it, err := c.Get(ctx, pb.GetRequest_builder{Id: args[0]}.Build())
				if err != nil {
					return err
				}
				return printJSON(it)
			})
		},
	}
}

func addCmd(addr *string, insc *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "add", Short: "Добавить запись"}
	var meta string
	login := &cobra.Command{Use: "login", Short: "Логин/пароль", RunE: func(cmd *cobra.Command, _ []string) error {
		url := flagOrPrompt(cmd, "url", "URL")
		user := flagOrPrompt(cmd, "username", "Логин")
		pass, err := flagOrPromptSecret(cmd, "password", "Пароль")
		if err != nil {
			return err
		}
		return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
			it, err := c.Create(ctx, pb.UpsertRequest_builder{
				Type: "login", Metadata: meta,
				Login: pb.LoginPayload_builder{Url: url, Username: user, Password: pass}.Build(),
			}.Build())
			if err != nil {
				return err
			}
			fmt.Println(it.GetId())
			return nil
		})
	}}
	login.Flags().String("url", "", "")
	login.Flags().String("username", "", "")
	login.Flags().String("password", "", "")

	text := &cobra.Command{Use: "text", Short: "Текст", RunE: func(cmd *cobra.Command, _ []string) error {
		title := flagOrPrompt(cmd, "title", "Заголовок")
		body := flagOrPrompt(cmd, "body", "Текст")
		return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
			it, err := c.Create(ctx, pb.UpsertRequest_builder{
				Type: "text", Metadata: meta,
				Text: pb.TextPayload_builder{Title: title, Body: body}.Build(),
			}.Build())
			if err != nil {
				return err
			}
			fmt.Println(it.GetId())
			return nil
		})
	}}
	text.Flags().String("title", "", "")
	text.Flags().String("body", "", "")

	card := &cobra.Command{Use: "card", Short: "Банковская карта", RunE: func(cmd *cobra.Command, _ []string) error {
		holder := flagOrPrompt(cmd, "holder", "Держатель")
		number := flagOrPrompt(cmd, "number", "Номер")
		expMonth := flagOrPrompt(cmd, "exp-month", "Месяц")
		expYear := flagOrPrompt(cmd, "exp-year", "Год")
		cvv, err := flagOrPromptSecret(cmd, "cvv", "CVV")
		if err != nil {
			return err
		}
		return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
			it, err := c.Create(ctx, pb.UpsertRequest_builder{
				Type: "card", Metadata: meta,
				Card: pb.CardPayload_builder{
					Holder:   holder,
					Number:   number,
					ExpMonth: expMonth,
					ExpYear:  expYear,
					Cvv:      cvv,
				}.Build(),
			}.Build())
			if err != nil {
				return err
			}
			fmt.Println(it.GetId())
			return nil
		})
	}}
	card.Flags().String("holder", "", "")
	card.Flags().String("number", "", "")
	card.Flags().String("exp-month", "", "")
	card.Flags().String("exp-year", "", "")
	card.Flags().String("cvv", "", "")

	var file string
	binary := &cobra.Command{Use: "binary", Short: "Файл", RunE: func(_ *cobra.Command, _ []string) error {
		if file == "" {
			return fmt.Errorf("--file обязателен")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
			it, err := c.Create(ctx, pb.UpsertRequest_builder{
				Type: "binary", Metadata: meta,
				Binary: pb.BinaryPayload_builder{Filename: file, Data: data}.Build(),
			}.Build())
			if err != nil {
				return err
			}
			fmt.Println(it.GetId())
			return nil
		})
	}}
	binary.Flags().StringVar(&file, "file", "", "путь к файлу")

	for _, c := range []*cobra.Command{login, text, card, binary} {
		c.Flags().StringVar(&meta, "meta", "", "текстовые метаданные")
		cmd.AddCommand(c)
	}
	return cmd
}

func editCmd(addr *string, insc *bool) *cobra.Command {
	var meta, typ string
	cmd := &cobra.Command{
		Use:   "edit <id>",
		Short: "Изменить запись (поля через флаги)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
				cur, err := c.Get(ctx, pb.GetRequest_builder{Id: args[0]}.Build())
				if err != nil {
					return err
				}
				req := pb.UpsertRequest_builder{
					Id: args[0], Type: cur.GetType(), Metadata: cur.GetMetadata(),
					Login: cur.GetLogin(), Text: cur.GetText(), Binary: cur.GetBinary(), Card: cur.GetCard(),
				}.Build()
				if typ != "" {
					req.SetType(typ)
				}
				if cmd.Flags().Changed("meta") {
					req.SetMetadata(meta)
				}
				if req.GetType() == "login" && req.HasLogin() {
					login := req.GetLogin()
					if v, _ := cmd.Flags().GetString("url"); cmd.Flags().Changed("url") {
						login.SetUrl(v)
					}
					if v, _ := cmd.Flags().GetString("username"); cmd.Flags().Changed("username") {
						login.SetUsername(v)
					}
					if v, _ := cmd.Flags().GetString("password"); cmd.Flags().Changed("password") {
						login.SetPassword(v)
					}
				}
				_, err = c.Update(ctx, req)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&meta, "meta", "", "")
	cmd.Flags().StringVar(&typ, "type", "", "")
	cmd.Flags().String("url", "", "")
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	return cmd
}

func rmCmd(addr *string, insc *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Удалить запись",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
				_, err := c.Delete(ctx, pb.DeleteRequest_builder{Id: args[0]}.Build())
				return err
			})
		},
	}
}

func syncCmd(addr *string, insc *bool) *cobra.Command {
	var since int64
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Забрать изменения с сервера",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withVault(*addr, *insc, func(ctx context.Context, c pb.VaultServiceClient) error {
				resp, err := c.Sync(ctx, pb.SyncRequest_builder{SinceVersion: since}.Build())
				if err != nil {
					return err
				}
				fmt.Println("server_version", resp.GetServerVersion())
				return printJSON(resp.GetItems())
			})
		},
	}
	cmd.Flags().Int64Var(&since, "since", 0, "версия, после которой забирать дельту")
	return cmd
}

func credentialsFromArgs(args []string) (string, string, error) {
	login := os.Getenv("GOPHKEEPER_LOGIN")
	if len(args) > 0 {
		login = args[0]
	}
	if login == "" {
		fmt.Fprint(os.Stderr, "логин: ")
		if _, err := fmt.Scanln(&login); err != nil {
			return "", "", err
		}
	}
	pass := os.Getenv("GOPHKEEPER_PASSWORD")
	if pass == "" {
		fmt.Fprint(os.Stderr, "пароль: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", "", err
		}
		pass = string(b)
	}
	return strings.TrimSpace(login), pass, nil
}

func flagOrPrompt(cmd *cobra.Command, name, label string) string {
	v, _ := readFlagOrPrompt(cmd, name, label, false)
	return v
}

func flagOrPromptSecret(cmd *cobra.Command, name, label string) (string, error) {
	return readFlagOrPrompt(cmd, name, label, true)
}

func readFlagOrPrompt(cmd *cobra.Command, name, label string, secret bool) (string, error) {
	if v, err := cmd.Flags().GetString(name); err == nil && v != "" {
		return v, nil
	}
	fmt.Fprint(os.Stderr, label+": ")
	if secret {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	var v string
	_, _ = fmt.Scanln(&v)
	return v, nil
}

func saveTokens(cfg clientcfg.Config, resp *pb.TokenResponse, addr string, inscFlag bool) error {
	if addr != "" {
		cfg.Address = addr
	}
	cfg.Insecure = inscFlag
	cfg.Token = resp.GetAccessToken()
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

func withAuthClient(addr string, inscFlag, needToken bool, fn func(context.Context, pb.AuthServiceClient, clientcfg.Config) error) error {
	cfg, conn, ctx, cancel, err := dial(addr, inscFlag, needToken)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()
	return fn(ctx, pb.NewAuthServiceClient(conn), cfg)
}

func withVault(addr string, inscFlag bool, fn func(context.Context, pb.VaultServiceClient) error) error {
	_, conn, ctx, cancel, err := dial(addr, inscFlag, true)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()
	return fn(ctx, pb.NewVaultServiceClient(conn))
}

func dial(addr string, inscFlag, needToken bool) (clientcfg.Config, *grpc.ClientConn, context.Context, context.CancelFunc, error) {
	cfg, err := clientcfg.Load()
	if err != nil {
		return cfg, nil, nil, nil, err
	}
	if addr != "" {
		cfg.Address = addr
	}
	if inscFlag {
		cfg.Insecure = true
	}
	var creds credentials.TransportCredentials
	if cfg.Insecure {
		creds = insecure.NewCredentials()
	} else {
		explicit := ""
		if tlsCertFlag != nil {
			explicit = *tlsCertFlag
		}
		tlsCfg, err := loadVerifiedTLS(cfg, explicit)
		if err != nil {
			return cfg, nil, nil, nil, err
		}
		creds = credentials.NewTLS(tlsCfg)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	conn, err := grpc.NewClient(cfg.Address, opts...)
	if err != nil {
		return cfg, nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if needToken {
		if cfg.Token == "" {
			cancel()
			_ = conn.Close()
			return cfg, nil, nil, nil, fmt.Errorf("сначала выполните gophkeeper login")
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.Token)
	}
	return cfg, conn, ctx, cancel, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
