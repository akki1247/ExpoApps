import { ThemedView } from "./ThemedView";
import { ThemedText } from "./ThemedText";
import { useAuth } from "@/context/auth";
import SignUpWithGoogleButton from "./SignUpWithGoogleButton";
import { View, StyleSheet } from "react-native";

export default function SignupForm() {
  const { signUp, isLoading } = useAuth();

  return (
    <ThemedView style={styles.container}>
      <View style={styles.card}>
        <ThemedText type="subtitle" style={styles.title}>
          Create your account
        </ThemedText>
        <SignUpWithGoogleButton onPress={signUp} disabled={isLoading} />
      </View>
    </ThemedView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center", alignItems: "center", padding: 16 },
  card: { width: "100%", maxWidth: 360, alignItems: "center" },
  title: { textAlign: "center", fontSize: 30, marginBottom: 24 },
}); 