package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	hscrack "github.com/bluesky0125/brute38/core"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"
	"github.com/orientwalt/usdp/accounts/keystore"
	hstype "github.com/orientwalt/usdp/types"
	hsutils "github.com/orientwalt/usdp/utils"
	htdfservice "github.com/orientwalt/usdp/x/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/libs/bech32"
)

var bech32Prefixes = []string{"cosmos", "cosmospub", "cosmosvaloper", "cosmosvaloperpub", "cosmosvalcons", "cosmosvalconspub"}

// MakeCodec generates the necessary codecs for Amino
func MakeCodec() *codec.Codec {
	var cdc = codec.New()
	codec.RegisterCrypto(cdc)
	return cdc
}

// Executor wraps the cobra Command with a nicer Execute method
type Executor struct {
	*cobra.Command
	Exit func(int) // this is os.Exit by default, override in tests
}

//
type ExitCoder interface {
	ExitCode() int
}

// execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func (e Executor) Execute() error {
	e.SilenceUsage = true
	e.SilenceErrors = true
	err := e.Command.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)

		// return error code 1 by default, can override it with a special error type
		exitCode := 1
		if ec, ok := err.(ExitCoder); ok {
			exitCode = ec.ExitCode()
		}
		e.Exit(exitCode)
	}
	return err
}

func main() {
	cobra.EnableCommandSorting = false

	cdc := MakeCodec()

	rootCmd := &cobra.Command{
		Use:   "hsutil",
		Short: "htdfservice utilities",
	}

	rootCmd.AddCommand(
		TestCmdBech2Hex(cdc),
		TestCmdHex2Bech(cdc),
		TestCmdHex2Json(cdc),
		TestCmdJSON2Hex(cdc),
		TestCmdSystemIssuer(cdc),
		TestCmdKeyRecover(cdc),
		TestCmdKeyUnlock(cdc),
		TestCmdKeyBruteForce(cdc),
	)
	executor := Executor{rootCmd, os.Exit}
	err := executor.Execute()
	if err != nil {
		panic(err)
	}
}

// junying-todo-20190412
func TestCmdBech2Hex(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:     "bech2hex [bech32addr]",
		Aliases: []string{"bh"},
		Short:   "validate/convert bech32 to hex",
		Long:    "hsutil bech cosmos1nlk39wzz7ymvr8utf3tcrkvaayunylmmyv05re",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			hrp, bz, err := bech32.DecodeAndConvert(args[0])
			if err != nil {
				fmt.Println("Not a valid bech32 string")
				return err
			}
			fmt.Println("Bech32 parse:")
			fmt.Printf("Human readible part: %v\nBytes (hex): %X\n",
				hrp,
				bz,
			)
			return nil
		},
	}
}

// junying-todo-20190412
func TestCmdHex2Bech(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:     "hex2bech [hexaddr]",
		Aliases: []string{"hb"},
		Short:   "validate/convert hex address to bech address",
		Long:    "hsutil bech cosmos1nlk39wzz7ymvr8utf3tcrkvaayunylmmyv05re",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bz, err := hex.DecodeString(args[0])
			if err != nil {
				fmt.Println("Not a valid hex string")
				return err
			}
			//fmt.Println("Hex parse:")
			//fmt.Println("Bech32 formats:")
			for _, prefix := range bech32Prefixes {
				bech32Addr, err := bech32.ConvertAndEncode(prefix, bz)
				if err != nil {
					return err
				}
				fmt.Println("  - " + bech32Addr)
			}
			return nil
		},
	}
}

// junying-todo-20190412
func TestCmdHex2Json(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:     "hex2json [rawhex]",
		Aliases: []string{"hj"},
		Short:   "decode rawhex to string",
		Long:    "hsutil hex2json 231..132",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc).WithAccountDecoder(cdc)
			decoded, err := htdfservice.Decode_Hex(args[0])
			if err != nil {
				fmt.Println("Not a valid hex string")
				return err
			}
			fmt.Fprintf(cliCtx.Output, "%s\n", decoded)
			return nil
		},
	}
}

// junying-todo-20190412
func TestCmdJSON2Hex(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:     "json2hex [json]",
		Aliases: []string{"jh"},
		Short:   "encode string to rawhex",
		Long:    "hsutil json2hex '{}'",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc).WithAccountDecoder(cdc)
			encoded := htdfservice.Encode_Hex([]byte(args[0]))
			fmt.Fprintf(cliCtx.Output, "%s\n", encoded)
			return nil
		},
	}
}

// junying-todo-20190412
func TestCmdSystemIssuer(cdc *codec.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "chkissuer",
		Aliases: []string{"ci"},
		Short:   "return the system issuer address",
		Long:    "hsutil chkissuer",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc).WithAccountDecoder(cdc)

			GenFilePath := viper.GetString(hstype.FlagGenFilePath)
			if GenFilePath == "" {
				fmt.Print("--genfile required. please indicate the path of genesis.json.\n")
				return nil
			}
			systemissuer, err := hsutils.GetSystemIssuerFromFile(GenFilePath)
			if err != nil {
				return err
			}

			fmt.Fprintf(cliCtx.Output, "%s\n", sdk.AccAddress.String(systemissuer))
			return nil
		},
	}
	cmd.Flags().String(hstype.FlagGenFilePath, "", "genesis.json file path")
	viper.BindPFlag(hstype.FlagGenFilePath, cmd.Flags().Lookup(hstype.FlagGenFilePath))
	cmd.MarkFlagRequired(hstype.FlagGenFilePath)
	return cmd
}

// junying-todo-20190425
func TestCmdKeyRecover(cdc *codec.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "recover",
		Aliases: []string{"rc"},
		Short:   "return the system issuer address",
		Long:    "hsutil recover",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			//cliCtx := context.NewCLIContext().WithCodec(cdc).WithAccountDecoder(cdc)

			buf := client.BufferStdin()
			account := uint32(viper.GetInt("account"))
			index := uint32(viper.GetInt("index"))
			// Get bip39 mnemonic
			var mnemonic string
			var bip39Passphrase string

			bip39Message := "Enter your bip39 mnemonic:"

			mnemonic, err := client.GetString(bip39Message, buf)
			if err != nil {
				return err
			}

			if !bip39.IsMnemonicValid(mnemonic) {
				fmt.Fprintf(os.Stderr, "Error: Mnemonic is not valid")
				return nil
			}
			// override bip39 passphrase
			bip39Passphrase, err = client.GetString(
				"Enter your bip39 passphrase. This is combined with the mnemonic to derive the seed. "+
					"Most users should just hit enter to use the default, \"\"", buf)
			if err != nil {
				return err
			}

			// if they use one, make them re-enter it
			if len(bip39Passphrase) != 0 {
				p2, err := client.GetString("Repeat the passphrase:", buf)
				if err != nil {
					return err
				}

				if bip39Passphrase != p2 {
					return errors.New("passphrases don't match")
				}
			}
			encryptPassword, err := client.GetCheckPassword(
				"Enter a passphrase to encrypt your key to disk:",
				"Repeat the passphrase:", buf)
			if err != nil {
				return err
			}
			key, err := keystore.GenerateKeyEx(mnemonic, bip39Passphrase, encryptPassword, account, index)
			if err != nil {
				return err
			}
			bech32addr := key.Address
			fmt.Print(bech32addr, "\n")
			err = keystore.StoreKeyEx(key)
			if err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}

// junying-todo-20190425
func TestCmdKeyUnlock(cdc *codec.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "unlock",
		Aliases: []string{"ul"},
		Short:   "unlock keyfile",
		Long:    "hsutil unlock [addr]",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := hsutils.UnlockByStdIn(args[0])
			if err != nil {
				fmt.Print("unlock failed!\n")
				return nil
			}
			fmt.Print("unlock succeed!\n")
			return nil
		},
	}
	return cmd
}

// junying-todo-20190426
func TestCmdKeyBruteForce(cdc *codec.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "bruteforce",
		Aliases: []string{"bf"},
		Short:   "unlock keyfile",
		Long:    "hsutil unlock [addr]",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			//cliCtx := context.NewCLIContext().WithCodec(cdc).WithAccountDecoder(cdc)
			charset := viper.GetString("charset")
			pattern := viper.GetString("pattern")
			pwlen := viper.GetInt("pwlen")
			hscrack.UnlockBruteForce(args[0], charset, pattern, pwlen)
			return nil
		},
	}
	cmd.Flags().String("charset", "", "charset for password")
	cmd.Flags().String("pattern", "", "password pattern")
	cmd.Flags().String("pwlen", "", "password length")
	viper.BindPFlag("charset", cmd.Flags().Lookup("charset"))
	viper.BindPFlag("pattern", cmd.Flags().Lookup("pattern"))
	viper.BindPFlag("pwlen", cmd.Flags().Lookup("pwlen"))
	return cmd
}
